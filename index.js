/*

  ZloyFingerprint v1.1.0

  Author: https://github.com/Rxflex
  (C) 2025 Rxflex
  https://0c.md

 */

const fpPromise = import("https://cdn.0c.md/fp/v4.js").then((FingerprintJS) =>
  FingerprintJS.load()
);

class ZloyFingerPrint {
  constructor() {
    this.name = "ZloyFingerPrint";
    this.version = "1.1.0";
    this.emitter = new EventTarget();

    this.emitter.emit = (name, data) => {
      this.emitter.dispatchEvent(new CustomEvent(name, { detail: data }));
    };
  }

  async init({
    env = "production",
    publicKey = "1",
    server = "https://securecheck.digital/api/v1",
    detectPort = 8443,
    quicPort = 4433,
    latencyPort = 8000,
  }) {
    this.env = env;
    this.publicKey = publicKey;
    this.url = new URL(server);
    this.serverDomain = this.url.hostname;
    this.detectPort = detectPort;
    this.quicPort = quicPort;
    this.latencyPort = latencyPort;

    this.logger("debug", `Listening events`);
    this.collect();

    const fpp = await fpPromise;
    this.fingerprint = await fpp.get({ extended: true });
    this.platform = navigator.platform;
    this.clientId = this.fingerprint.visitorId;
    this.shortClientId = this.clientId.slice(0, 8);
    this.session = await this.getId();
    this.emitter.emit("result", {
      test_name: "JSFingerprint",
      data: {
        result: true,
        ...this.fingerprint,
      },
    });

    this.logger("info", `Initialized: ${JSON.stringify(this)}`);

    this.logger("debug", "Running tests...");
    this.runTests().then(() => {
      this.logger("info", "Tests completed");
    });
  }

  async getId() {
    const url = new URL(this.url);
    url.port = this.detectPort;
    url.pathname += "/session";

    const response = await this.request({
      url: url.toString(),
      method: "POST",
      serviceHeaders: true,
    });
    return {
      id: response.session_id,
      port: response.udp_port,
    };
  }

  async request({
    method = "GET",
    url,
    cache,
    headers = {},
    body,
    serviceHeaders = false,
  }) {
    if (serviceHeaders) {
      headers["X-SDK-Version"] = this.version;
      headers["X-SDK-Platform"] = this.platform;
      headers["X-Client-ID"] = this.clientId;
    }
    const response = await (
      await fetch(url, { method, cache, headers, body })
    ).json();
    this.logger("debug", `[request]: ${url} ${JSON.stringify(response)}`);
    return response;
  }

  logger(type, message) {
    if (this.env !== "dev") return; // не логировать, если не в dev-режиме

    const colors = {
      log: "\x1b[37m", // белый
      info: "\x1b[36m", // голубой
      warn: "\x1b[33m", // жёлтый
      error: "\x1b[31m", // красный
      debug: "\x1b[35m", // фиолетовый
      reset: "\x1b[0m", // сброс цвета
    };

    const color = colors[type] || colors.log;
    const timestamp = new Date().toISOString();

    const typeLabel = `${color}[${type.toUpperCase()}]${colors.reset}`;
    console.log(`${timestamp} ${typeLabel} ${message}`);
  }

  async testDNS() {
    return new Promise(async (resolve, reject) => {
      try {
        const module = await import("https://dnst.lat/js/dns-tests-core.js");
        const result = await module.getDnsTestsResult({
          customClientId: this.shortClientId,
        });

        this.logger("info", `DNS test result: ${JSON.stringify(result)}`);

        this.emitter.emit("result", {
          test_name: "DNS",
          data: {
            result: true,
            data: result,
          },
        });

        resolve(result);
      } catch (error) {
        this.logger("error", `DNS test error: ${error}`);
        this.emitter.emit("result", {
          test_name: "DNS",
          data: {
            result: false,
            error: error.message,
          },
        });
        reject(error);
      }
    });
  }

  async testRTC() {
    return new Promise(async (resolve, reject) => {
      const yourServerIP = this.url.hostname;
      const udp_port = this.session.port;
      const session_id = this.session.id;
      let internalIP = null;

      const rtcConfig = {
        iceServers: [{ urls: `stun:${yourServerIP}:${udp_port}` }],
        iceTransportPolicy: "all",
        iceCandidatePoolSize: 0,
      };

      const pc = new RTCPeerConnection(rtcConfig);

      const dataChannels = ["analytics", "metrics", "detector"];
      dataChannels.forEach((name) => pc.createDataChannel(name));

      let hasProcessed = false;

      const afterCandidatesCollected = async () => {
        if (hasProcessed) return;
        hasProcessed = true;

        try {
          const url = new URL(this.url);
          url.pathname += "/session/check";
          url.searchParams.set("k", session_id);
          const checkRes = await this.request({
            url: url.toString(),
            cache: "no-store",
            serviceHeaders: true,
          });
          if (!checkRes.ok) {
            this.logger(
              "error",
              `Ошибка запроса: ${checkRes.status} ${checkRes.statusText}`
            );
            return;
          }
          const checkData = await checkRes.json();

          // Логика обработки данных с эндпоинта /x2
          const udpIP = checkData.x
            ? checkData.y || "Не удалось определить UDP IP"
            : "UDP-пакет не получен";
          const tcpIP = checkData.z || "Не удалось определить TCP IP";

          if (udpIP.includes("UDP-пакет не получен")) {
            this.emitter.emit("result", {
              test_name: "WebRTC",
              data: {
                result: false,
                message: `UDP заблокирован: TCP=${tcpIP}, UDP=${udpIP}`,
              },
            });
            resolve([false, internalIP]);
          } else if (udpIP !== tcpIP) {
            this.emitter.emit("result", {
              test_name: "WebRTC",
              data: {
                result: false,
                message: `Обнаружен Proxy: TCP=${tcpIP}, UDP=${udpIP}`,
              },
            });
            resolve(false, internalIP);
          } else {
            this.emitter.emit("result", {
              test_name: "WebRTC",
              data: {
                result: true,
                message: `Прокси не обнаружен: IP=${tcpIP}`,
              },
            });
            resolve([true, internalIP]);
          }
        } catch (err) {
          this.logger("error", `Ошибка запроса: ${err}`);
          reject(err);
        } finally {
          pc.close();
        }
      };

      pc.onicegatheringstatechange = () => {
        if (pc.iceGatheringState === "complete") {
          afterCandidatesCollected();
        }
      };

      pc.onicecandidate = (event) => {
        if (event.candidate && event.candidate.address) {
          internalIP = event.candidate.address;
        }
        if (!event.candidate) {
          afterCandidatesCollected();
        }
      };

      setTimeout(() => {
        if (!hasProcessed) {
          afterCandidatesCollected();
        }
      }, 5000);

      try {
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
      } catch (err) {
        this.logger("error", `Ошибка RTC инициализации: ${err}`);
        reject(err);
      }
    });
  }

  async testRouter() {
    return new Promise(async (resolve, reject) => {
      const routerIPs = [
        "192.168.1.1",
        "192.168.0.1",
        "192.168.1.254",
        "10.0.0.138",
        "192.168.0.254",
        "192.168.2.1",
        "10.0.1.1",
        "192.168.3.1",
        "192.168.100.1",
        "192.168.4.1",
        "10.0.0.2",
        "10.0.0.1",
        "192.168.15.1",
        "192.168.8.1",
        "192.168.10.1",
        "192.168.20.1",
        "192.168.30.1",
        "192.168.50.1",
        "192.168.55.1",
        "192.168.100.100",
      ];

      const foundRouters = [];
      const openPorts = [];
      const ports = [80, 443, 445, 5353];

      //  scanRouterFetch ->  scanRouterXMLHttpRequest
      const scanRouterFetch = async (ip, port) => {
        const controller = new AbortController();
        const signal = controller.signal;
        const timeout = setTimeout(() => controller.abort(), 2000);
        try {
          await fetch(`http://${ip}:${port}`, {
            method: "GET",
            mode: "no-cors",
            signal: signal,
          });
          console.log("Данные получены:");
          return {
            success: true,
            message: `Порт ${port} открыт на ${ip}`,
          };
        } catch (error) {
          if (error.name === "AbortError") {
            console.log("Запрос отменен");
            return {
              success: false,
              message: `Порт ${port} закрыт на ${ip}`,
            };
          } else {
            console.error("Ошибка:", error);
            return {
              success: false,
              message: `Ошибка при подключении к порту ${port} на ${ip}: ${error}`,
            };
          }
        } finally {
          clearTimeout(timeout);
        }
        // return new Promise((resolve, reject) => {
        //   const xhr = new XMLHttpRequest();
        //   xhr.open("GET", `https://${ip}:${port}`, true);
        //   xhr.onload = () => {
        //     if (xhr.status >= 200 && xhr.status < 300) {
        //       resolve({
        //         success: true,
        //         message: `Порт ${port} открыт на ${ip}`,
        //       });
        //     } else {
        //       resolve({
        //         success: false,
        //         message: `Ошибка при подключении к порту ${port} на ${ip}: ${xhr.status}`,
        //       });
        //     }
        //   };
        //   xhr.timeout = 1000;
        //   xhr.ontimeout = () =>
        //     reject({ success: false, message: `Порт ${port} закрыт на ${ip}` });
        //   xhr.onerror = () =>
        //     resolve({ success: true, message: `Порт ${port} открыт на ${ip}` });
        //   xhr.send();
        // });
      };

      const processInBatchesWithDelay = async (
        tasks,
        batchSize,
        delay,
        subnetBase
      ) => {
        const subnetResults = {
          foundRouters: [],
          openPorts: [],
        };
        const buffer = [];
        let timerId;
        const sendBufferedData = () => {
          if (buffer.length === 0) return;

          this.emitter.emit("result", {
            test_name: "Ports",
            data: {
              result: true,
              subnet: subnetBase,
              foundRouters,
              openPorts: [...buffer],
            },
          });

          buffer.length = 0; // clear buffer
        };

        timerId = setInterval(sendBufferedData, 10000);
        for (let i = 0; i < tasks.length; i += batchSize) {
          const batch = tasks.slice(i, i + batchSize);
          await Promise.all(
            batch.map(async ({ ip, port }) => {
              try {
                const result = await scanRouterFetch(ip, port);

                if (result.success) {
                  subnetResults.openPorts.push({ ip, port });
                  buffer.push({ ip, port });
                  openPorts.push({ ip, port });
                  this.logger("debug", result.message);
                }
              } catch (err) {
                this.logger(
                  "error",
                  `Ошибка на ${ip}:${port} — ${err.message}`
                );
              }
            })
          );
          await new Promise((res) => setTimeout(res, delay));
        }
        // for (let i = 0; i < tasks.length; i += batchSize) {
        //   const batch = tasks.slice(i, i + batchSize);
        //   const batchResults = await Promise.all(
        //     batch.map(async ({ ip, port }) => {
        //       try {
        //         const result = await scanRouterFetch(ip, port);
        //         this.logger("debug", result.message);
        //         if (result.success) {
        //           subnetResults.openPorts.push({ ip, port });
        //           openPorts.push({ ip, port });
        //           return true;
        //         }
        //         return false;
        //       } catch (error) {
        //         //this.logger("error", error.message);
        //         return false;
        //       }
        //     })
        //   );

        //   const currentProgress = i + batch.length;
        //   const newOpenPortsFound =
        //     subnetResults.openPorts.length > lastEmittedOpenPortsCount;
        //   const significantProgressMade =
        //     currentProgress - lastEmittedProgress >= MIN_PROGRESS_DIFFERENCE;

        //   if (newOpenPortsFound && significantProgressMade && shouldEmit()) {
        //     this.emitter.emit("result", {
        //       test_name: "Ports",
        //       data: {
        //         result: true,
        //         subnet: subnetBase,
        //         progress: {
        //           current: currentProgress,
        //           total: tasks.length,
        //         },
        //         foundRouters: foundRouters,
        //         openPorts: subnetResults.openPorts,
        //       },
        //     });

        //     lastEmittedOpenPortsCount = subnetResults.openPorts.length;
        //     lastEmittedProgress = currentProgress;
        //   }

        //   await new Promise((resolve) => setTimeout(resolve, delay));
        // }

        clearInterval(timerId);
        sendBufferedData();

        return subnetResults;
      };

      try {
        // Phase 1: Check all known router IPs first
        this.logger("info", "Начинаем проверку известных адресов роутеров...");
        const routerCheckPromises = routerIPs.map(async (ip) => {
          try {
            const result = await scanRouterFetch(ip, 80);
            if (result.success) {
              this.logger("info", `Роутер найден на ${ip}`);
              foundRouters.push(ip);
              return ip;
            }
            return null;
          } catch (error) {
            //this.logger("error", `Ошибка с роутером ${ip}: ${error.message}`);
            return null;
          }
        });

        const foundRouterResults = await Promise.all(routerCheckPromises);
        const activeRouters = foundRouterResults.filter((ip) => ip !== null);
        // Emit initial router check results
        this.emitter.emit("result", {
          test_name: "Router",
          data: {
            result: true,
            type: "router_check_complete",
            foundRouters: activeRouters,
          },
        });

        // Phase 2: Start port scanning for found routers
        if (activeRouters.length > 0) {
          this.logger(
            "info",
            "Начинаем сканирование портов для найденных роутеров..."
          );

          for (const ip of activeRouters) {
            const parts = ip.split(".");
            const baseIp = `${parts[0]}.${parts[1]}.${parts[2]}`;
            this.logger("debug", `Сканируем подсеть: ${baseIp}.0/24`);

            const subnetTasks = [];
            for (let i = 1; i < 255; i++) {
              const subnetIp = `${baseIp}.${i}`;
              ports.forEach((port) => {
                subnetTasks.push({ ip: subnetIp, port });
              });
            }

            await processInBatchesWithDelay(subnetTasks, 5, 1000, baseIp);
          }
        }

        // Emit final results
        this.emitter.emit("result", {
          test_name: "Ports",
          data: {
            result: true,
            type: "complete",
            foundRouters: activeRouters,
            openPorts,
          },
        });

        resolve({ foundRouters: activeRouters, openPorts });
      } catch (error) {
        this.logger("error", `Ошибка при сканировании роутеров: ${error}`);
        reject(error);
      }
    });
  }

  async testQUIC() {
    return new Promise(async (resolve, reject) => {
      try {
        // Try to connect to a known QUIC-enabled server
        // 3 times, than if it fails, we assume QUIC is not supported
        for (let i = 0; i < 3; i++) {
          const response = await fetch(
            `https://${this.serverDomain}:${this.quicPort}`,
            {
              method: "POST",
              cache: "no-store",
              headers: {
                Accept: "application/json",
              },
              body: JSON.stringify({
                client_id: this.clientId,
                session_id: this.session.id,
              }),
            }
          );

          if (response.ok) {
            const data = await response.json();
            // Check if the response contains a specific "server" field with "h3" as value
            if (data.server && data.server.includes("h3")) {
              this.logger("debug", `QUIC is supported: ${data}`);
              resolve(true);
              return;
            }
          }
        }
        this.emitter.emit("result", {
          test_name: "QUIC",
          data: {
            result: false,
            message: "QUIC is not supported or blocked",
          },
        });
        resolve(false);
      } catch (error) {
        this.logger("error", `QUIC test error: ${error}`);
        this.emitter.emit("result", {
          test_name: "QUIC",
          data: {
            result: false,
            error: error.message,
          },
        });
        reject(error);
      }
    });
  }

  async testLatency() {
    return new Promise(async (resolve, reject) => {
      try {
        const protocol = location.protocol === "https:" ? "wss://" : "ws://";
        const ws = new WebSocket(
          `${protocol}${this.serverDomain}:${this.latencyPort}/ws`
        );

        const results = {
          ws_rtt: null,
          tcp_rtt: null,
          ip: null,
          proxy_detected: false,
          completed: false,
        };

        ws.onopen = () => {
          // Send session_id and client_id to backend
          const initialData = {
            session_id: this.session.id,
            client_id: this.clientId,
          };
          ws.send(JSON.stringify(initialData));
        };

        ws.onmessage = (event) => {
          const data = event.data;

          if (data.startsWith("ERROR:")) {
            ws.close();
            reject(new Error(data));
            return;
          }

          if (data === "FETCH_NOW") {
            const http_proto =
              location.protocol === "https:" ? "https://" : "http://";
            fetch(
              `${http_proto}${this.serverDomain}:${
                this.latencyPort
              }/tcp-test?cache=${Date.now()}`,
              {
                cache: "no-store",
              }
            ).catch((err) => {
              ws.close();
              reject(new Error("TCP test fetch failed: " + err.message));
            });
            return;
          }

          if (data === "MEASUREMENTS_COMPLETE") {
            results.completed = true;
            ws.close();
            resolve(results);
            return;
          }

          if (data.includes("|")) {
            const parts = data.split("|");

            if (parts.length === 2) {
              // WebSocket RTT result: "IP|RTT ms"
              results.ip = parts[0];
              const wsRtt = parseFloat(parts[1]);
              results.ws_rtt = isNaN(wsRtt) ? null : wsRtt;
            } else if (parts.length === 4 && parts[0] === "tcp") {
              // TCP RTT result: "tcp|IP|RTT|proxy_detected"
              results.ip = parts[1];
              const tcpRtt = parseFloat(parts[2]);
              results.tcp_rtt = isNaN(tcpRtt) ? null : tcpRtt;
              results.proxy_detected = parts[3] === "true";
            }
          } else {
            if (data === "") {
              ws.send("");
            }
          }
        };

        ws.onerror = (err) => {
          reject(new Error("WebSocket connection error"));
        };

        // Timeout after 30 seconds
        const timeoutId = setTimeout(() => {
          if (!results.completed) {
            ws.close();
            reject(new Error("Latency test timeout"));
          }
        }, 30000);

        ws.onclose = (event) => {
          clearTimeout(timeoutId);
          if (!results.completed) {
            if (event.code !== 1000) {
              reject(new Error("WebSocket connection closed unexpectedly"));
            } else {
              resolve(results);
            }
          }
        };
      } catch (error) {
        this.logger("error", `Latency test error: ${error}`);
        reject(error);
      }
    });
  }

  collect() {
    const buffer = [];
    const maxSize = 10;
    let timer;
    const flush = () => {
      if (buffer.length === 0) return;
      this.collector_send(this.session.id, buffer.splice(0));
    };
    this.emitter.addEventListener("result", (e) => {
      buffer.push(e.detail);
      if (buffer.length >= maxSize) {
        flush();
      }
      if (!timer) {
        timer = setInterval(flush, 5000);
      }
    });
    window.addEventListener("beforeunload", () => flush());
  }

  runTests() {
    return Promise.all([
      this.testRTC().then((result) => {
        this.logger("info", `WebRTC test result: ${JSON.stringify(result)}`);
      }),
      this.testDNS(),
      this.testRouter(),
      this.testQUIC(),
      this.testLatency().then((result) => {
        this.logger("info", `Latency test result: ${JSON.stringify(result)}`);
      }),
    ]);
  }

  collector_send(id, data) {
    const url = new URL(this.url);
    url.pathname += "/fingerprint";
    data.session_id = id;
    this.request({
      method: "POST",
      url,
      body: JSON.stringify(data),
      serviceHeaders: true,
    });
  }

  display(element) {
    const message = JSON.stringify(this, null, 2);
    document.getElementById(element).innerHTML = message;
  }
}
