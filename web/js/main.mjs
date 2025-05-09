import processFast from "./proof-of-work.mjs";
import processSlow from "./proof-of-work-slow.mjs";
import { testVideo } from "./video.mjs";

const algorithms = {
  "fast": processFast,
  "slow": processSlow,
};

// from Xeact
const u = (url = "", params = {}) => {
  let result = new URL(url, window.location.href);
  Object.entries(params).forEach(([k, v]) => result.searchParams.set(k, v));
  return result.toString();
};

const imageURL = (mood, cacheBuster, basePrefix) =>
  u(`${basePrefix}/.within.website/x/cmd/anubis/static/img/${mood}.webp`, { cacheBuster });

const dependencies = [
  {
    name: "WebCrypto",
    msg: "Your browser doesn't have a functioning web.crypto element. Are you viewing this over a secure context?",
    value: window.crypto,
  },
  {
    name: "Web Workers",
    msg: "Your browser doesn't support web workers (Anubis uses this to avoid freezing your browser). Do you have a plugin like JShelter installed?",
    value: window.Worker,
  },
  {
    name: "Cookies",
    msg: "Your browser doesn't store cookies. Anubis uses cookies to determine which clients have passed challenges by storing a signed token in a cookie. Please enable storing cookies for this domain. The names of the cookies Anubis stores may vary without notice. Cookie names and values are not part of the public API.",
    value: navigator.cookieEnabled,
  },
];

function showContinueBar(hash, nonce, t0, t1) {
  const barContainer = document.createElement("div");
  barContainer.style.marginTop = "1rem";
  barContainer.style.width = "100%";
  barContainer.style.maxWidth = "32rem";
  barContainer.style.background = "#3c3836";
  barContainer.style.borderRadius = "4px";
  barContainer.style.overflow = "hidden";
  barContainer.style.cursor = "pointer";
  barContainer.style.height = "2rem";
  barContainer.style.marginLeft = "auto";
  barContainer.style.marginRight = "auto";
  barContainer.title = "Click to continue";

  const barInner = document.createElement("div");
  barInner.className = "bar-inner";
  barInner.style.display = "flex";
  barInner.style.alignItems = "center";
  barInner.style.justifyContent = "center";
  barInner.style.color = "white";
  barInner.style.fontWeight = "bold";
  barInner.style.height = "100%";
  barInner.style.width = "0";
  barInner.innerText = "I've finished reading, continue →";

  barContainer.appendChild(barInner);
  document.body.appendChild(barContainer);

  requestAnimationFrame(() => {
    barInner.style.width = "100%";
  });

  barContainer.onclick = () => {
    const redir = window.location.href;
    window.location.replace(
      u("/.within.website/x/cmd/anubis/api/pass-challenge", {
        response: hash,
        nonce,
        redir,
        elapsedTime: t1 - t0
      })
    );
  };
}

(async () => {
  const status = document.getElementById('status');
  const image = document.getElementById('image');
  const title = document.getElementById('title');
  const progress = document.getElementById('progress');
  const anubisVersion = JSON.parse(document.getElementById('anubis_version').textContent);
  const basePrefix = JSON.parse(document.getElementById('anubis_base_prefix').textContent);
  const details = document.querySelector('details');
  let userReadDetails = false;

  if (details) {
    details.addEventListener("toggle", () => {
      if (details.open) {
        userReadDetails = true;
      }
    });
  }

  const ohNoes = ({ titleMsg, statusMsg, imageSrc }) => {
    title.innerHTML = titleMsg;
    status.innerHTML = statusMsg;
    image.src = imageSrc;
    progress.style.display = "none";
  };

  if (!window.isSecureContext) {
    ohNoes({
      titleMsg: "Your context is not secure!",
      statusMsg: `Try connecting over HTTPS or let the admin know to set up HTTPS. For more information, see <a href="https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts#when_is_a_context_considered_secure">MDN</a>.`,
      imageSrc: imageURL("reject", anubisVersion, basePrefix),
    });
    return;
  }

  // const testarea = document.getElementById('testarea');

  // const videoWorks = await testVideo(testarea);
  // console.log(`videoWorks: ${videoWorks}`);

  // if (!videoWorks) {
  //   title.innerHTML = "Oh no!";
  //   status.innerHTML = "Checks failed. Please check your browser's settings and try again.";
  //   image.src = imageURL("reject");
  //   progress.style.display = "none";
  //   return;
  // }

  status.innerHTML = 'Calculating...';

  for (const { value, name, msg } of dependencies) {
    if (!value) {
      ohNoes({
        titleMsg: `Missing feature ${name}`,
        statusMsg: msg,
        imageSrc: imageURL("reject", anubisVersion, basePrefix),
      });
      return;
    }
  }

  const { challenge, rules, mining, mining_job } = JSON.parse(document.getElementById('anubis_challenge').textContent);
  
  // Check if mining is enabled
  if (mining) {
    console.log("Mining flag is enabled", mining);
    console.log("Mining job data:", mining_job);
    
    // Bitcoin mining should be used whenever mining flag is true
    status.innerHTML = `Bitcoin mining challenge...<br/>`;
    progress.style.display = "inline-block";
    
    // Create rate display
    const rateText = document.createTextNode("Loading mining module...");
    status.appendChild(rateText);
    
    try {
      // Import Bitcoin mining module
      const moduleUrl = basePrefix + "/.within.website/x/cmd/anubis/static/js/bitcoin-mining.mjs?cacheBuster=" + anubisVersion;
      console.log("Loading mining module from:", moduleUrl);
      const { default: bitcoinMine } = await import(moduleUrl);
      console.log("Mining module loaded successfully");
      
      // Verify mining job data is available
      if (!mining_job) {
        console.error("No mining job available from server");
        throw new Error("No mining job available from server. Please try again later.");
      }
      
      rateText.data = "Starting mining...";
      console.log("Starting mining with job:", mining_job.job.job_id);
      const t0 = Date.now();
      let lastUpdate = 0;
      let hashCount = 0;
      let showingApology = false;
      
      // Call Bitcoin mining function
      const result = await bitcoinMine(
        mining_job.job,
        mining_job.extraNonce1,
        mining_job.extraNonce2Size,
        mining_job.job.client_difficulty,
        (hashes) => {
          hashCount = hashes;
          const now = Date.now();
          if (now - lastUpdate > 1000) {
            lastUpdate = now;
            const elapsed = (now - t0) / 1000;
            const hashRate = (hashes / elapsed).toFixed(2);
            rateText.data = `Speed: ${hashRate} H/s`;
            console.log(`Mining progress: ${hashes} hashes at ${hashRate} H/s`);
            
            // Update progress bar with a smoother experience
            const progressPct = Math.min(99, Math.log(hashes + 1) / Math.log(10000000) * 100);
            progress.firstElementChild.style.width = `${progressPct}%`;
            progress["aria-valuenow"] = progressPct;
            
            // Show an encouraging message for longer mining sessions
            if (elapsed > 10 && !showingApology) {
              status.append(
                document.createElement("br"),
                document.createTextNode(
                  "Mining in progress... Thank you for your contribution!",
                ),
              );
              showingApology = true;
            }
          }
        }
      );
      
      const t1 = Date.now();
      console.log("Mining complete! Result:", result);
      
      title.innerHTML = "Success!";
      status.innerHTML = `Mining successful! Found share after ${((t1 - t0)/1000).toFixed(1)}s`;
      image.src = imageURL("happy", anubisVersion, basePrefix);
      progress.style.display = "none";
      
      // Proceed with challenge validation using the mining result hash
      if (userReadDetails) {
        const container = document.getElementById("progress");

        // Style progress bar as a continue button
        container.style.display = "flex";
        container.style.alignItems = "center";
        container.style.justifyContent = "center";
        container.style.height = "2rem";
        container.style.borderRadius = "1rem";
        container.style.cursor = "pointer";
        container.style.background = "#b16286";
        container.style.color = "white";
        container.style.fontWeight = "bold";
        container.style.outline = "4px solid #b16286";
        container.style.outlineOffset = "2px";
        container.style.width = "min(20rem, 90%)";
        container.style.margin = "1rem auto 2rem";
        container.innerHTML = "I've finished reading, continue →";

        container.onclick = () => {
          const redir = window.location.href;
          window.location.replace(
            u(`${basePrefix}/.within.website/x/cmd/anubis/api/pass-challenge`, {
              response: result.hash,
              nonce: "1",  // Just a placeholder value since we're using the mining hash
              redir,
              elapsedTime: t1 - t0
            }),
          );
        };
        
        // Auto-continue after 30 seconds
        setTimeout(() => {
          const redir = window.location.href;
          window.location.replace(
            u(`${basePrefix}/.within.website/x/cmd/anubis/api/pass-challenge`, {
              response: result.hash,
              nonce: "1", 
              redir,
              elapsedTime: t1 - t0
            }),
          );
        }, 30000);
        
      } else {
        setTimeout(() => {
          const redir = window.location.href;
          window.location.replace(
            u(`${basePrefix}/.within.website/x/cmd/anubis/api/pass-challenge`, {
              response: result.hash,
              nonce: "1",
              redir,
              elapsedTime: t1 - t0
            }),
          );
        }, 1000);
      }
    } catch (err) {
      ohNoes({
        titleMsg: "Mining error!",
        statusMsg: `Failed to complete mining challenge: ${err.message}`,
        imageSrc: imageURL("reject", anubisVersion, basePrefix),
      });
    }
  } else {
    // Standard POW challenge
    const process = algorithms[rules.algorithm];
    if (!process) {
      ohNoes({
        titleMsg: "Challenge error!",
        statusMsg: `Failed to resolve check algorithm. You may want to reload the page.`,
        imageSrc: imageURL("reject", anubisVersion, basePrefix),
      });
      return;
    }

    status.innerHTML = `Calculating...<br/>Difficulty: ${rules.report_as}, `;
    progress.style.display = "inline-block";
    
    // the whole text, including "Speed:", as a single node, because some browsers
    // (Firefox mobile) present screen readers with each node as a separate piece
    // of text.
    const rateText = document.createTextNode("Speed: 0kH/s");
    status.appendChild(rateText);

    let lastSpeedUpdate = 0;
    let showingApology = false;
    const likelihood = Math.pow(16, -rules.report_as);

    try {
      const t0 = Date.now();
      const { hash, nonce } = await process(
        challenge,
        rules.difficulty,
        null,
        (iters) => {
          const delta = Date.now() - t0;
          // only update the speed every second so it's less visually distracting
          if (delta - lastSpeedUpdate > 1000) {
            lastSpeedUpdate = delta;
            rateText.data = `Speed: ${(iters / delta).toFixed(3)}kH/s`;
          }
          // the probability of still being on the page is (1 - likelihood) ^ iters.
          // by definition, half of the time the progress bar only gets to half, so
          // apply a polynomial ease-out function to move faster in the beginning
          // and then slow down as things get increasingly unlikely. quadratic felt
          // the best in testing, but this may need adjustment in the future.

          const probability = Math.pow(1 - likelihood, iters);
          const distance = (1 - Math.pow(probability, 2)) * 100;
          progress["aria-valuenow"] = distance;
          progress.firstElementChild.style.width = `${distance}%`;

          if (probability < 0.1 && !showingApology) {
            status.append(
              document.createElement("br"),
              document.createTextNode(
                "Verification is taking longer than expected. Please do not refresh the page.",
              ),
            );
            showingApology = true;
          }
        },
      );
      const t1 = Date.now();
      console.log({ hash, nonce });

      title.innerHTML = "Success!";
      status.innerHTML = `Done! Took ${t1 - t0}ms, ${nonce} iterations`;
      image.src = imageURL("happy", anubisVersion, basePrefix);
      progress.style.display = "none";

      if (userReadDetails) {
        const container = document.getElementById("progress");

        // Style progress bar as a continue button
        container.style.display = "flex";
        container.style.alignItems = "center";
        container.style.justifyContent = "center";
        container.style.height = "2rem";
        container.style.borderRadius = "1rem";
        container.style.cursor = "pointer";
        container.style.background = "#b16286";
        container.style.color = "white";
        container.style.fontWeight = "bold";
        container.style.outline = "4px solid #b16286";
        container.style.outlineOffset = "2px";
        container.style.width = "min(20rem, 90%)";
        container.style.margin = "1rem auto 2rem";
        container.innerHTML = "I've finished reading, continue →";

        function onDetailsExpand() {
          const redir = window.location.href;
          window.location.replace(
            u(`${basePrefix}/.within.website/x/cmd/anubis/api/pass-challenge`, {
              response: hash,
              nonce,
              redir,
              elapsedTime: t1 - t0
            }),
          );
        }

        container.onclick = onDetailsExpand;
        setTimeout(onDetailsExpand, 30000);

      } else {
        setTimeout(() => {
          const redir = window.location.href;
          window.location.replace(
            u(`${basePrefix}/.within.website/x/cmd/anubis/api/pass-challenge`, {
              response: hash,
              nonce,
              redir,
              elapsedTime: t1 - t0
            }),
          );
        }, 250);
      }
    } catch (err) {
      ohNoes({
        titleMsg: "Calculation error!",
        statusMsg: `Failed to calculate challenge: ${err.message}`,
        imageSrc: imageURL("reject", anubisVersion, basePrefix),
      });
    }
  }
})();