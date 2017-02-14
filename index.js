let roots = null;
let req = new XMLHttpRequest();
req.open("GET", "KnownRootHashes.json", true);
req.onreadystatechange = function() {
  if (req.readyState == 4 && req.status == 200) {
    roots = JSON.parse(req.responseText);
    initializeTelemetry();
  }
}
req.send();

// A list of Entry
let entries = [];

let sortField = "telemetryID";
let sortDirection = 1;

// name: the name of the CA in question
// successCounts: a map of versionTuple -> successful validation count
// failureCounts: a map of versionTuple -> pinning failure count
function Entry(name, id, hash) {
  this.name = name.replace(/_/g, " ");
  this.telemetryID = id;
  this.hash = hash;
  this.successCounts = {};
  this.failureCounts = {};
  this.successCountsByDate = {};
  this.failureCountsByDate = {};
}

Entry.prototype = {
  MAX_CA_NAME_LEN: 50,
  name: '',
  telemetryID: -1,
  hash: '',
  successCounts: null,
  failureCounts: null,
  getName: function() {
    let result = this.name;
    if (result.length > this.MAX_CA_NAME_LEN) {
      result = result.substring(0, this.MAX_CA_NAME_LEN) + "...";
    }
    return result;
  },
  getHash: function() {
    let bytes = atob(this.hash);
    let hexBytes = [];
    for (let i = 0; i < bytes.length; i++) {
      let hexByte = bytes.charCodeAt(i).toString(16);
      if (hexByte.length != 2) {
        hexByte = "0" + hexByte;
      }
      hexBytes.push(hexByte);
    }
    let result = hexBytes.join(':');
    return result;
  },
  getEnabledSuccesses: function() {
    return this.getEnabledCount(this.successCounts);
  },
  getEnabledFailures: function() {
    return this.getEnabledCount(this.failureCounts);
  },
  getEnabledCount: function(countMap) {
    let sum = 0;
    for (let key of Object.keys(countMap)) {
      if (versionIsEnabled(key)) {
        sum += countMap[key];
      }
    }
    return sum;
  },
  successCountsByDate: null,
  failureCountsByDate: null,
  getEnabledSuccessTimeSeriesData: function() {
    return this.getEnabledTimeSeriesData(this.successCountsByDate);
  },
  getEnabledFailureTimeSeriesData: function() {
    return this.getEnabledTimeSeriesData(this.failureCountsByDate);
  },
  getEnabledTimeSeriesData: function(countMapsByDate) {
    let data = [];
    for (let millisString of Object.keys(countMapsByDate)) {
      let sum = this.getEnabledCount(countMapsByDate[millisString]);
      if (sum > 0) {
        data.push([parseInt(millisString), sum]);
      }
    }
    return data.sort(function(pair1, pair2) {
      return pair1[0] - pair2[0];
    });
  }
};

function initializeTelemetry() {
  Telemetry.init(function() {
    let versions = Telemetry.getVersions();
    for (let versionTuple of versions) {
      let [channel, version] = versionTuple.split("/");
      if (parseInt(version, 10) >= 45) {
        Telemetry.getFilterOptions(channel, version, (filterOptions) => {
          if (filterOptions.metric.includes("CERT_VALIDATION_SUCCESS_BY_CA") &&
              filterOptions.metric.includes("CERT_PINNING_FAILURES_BY_CA")) {
            let versionsForm = document.getElementById("versions");
            let checkbox = document.createElement("input");
            checkbox.id = "checkbox-" + versionTuple;
            checkbox.type = "checkbox";
            checkbox.value = versionTuple;
            checkbox.checked = true;
            versionsForm.appendChild(checkbox);
            let checkboxText = document.createElement("span");
            checkboxText.textContent = versionTuple;
            checkboxText.setAttribute("class", "inProgress");
            checkboxText.id = "checkboxText-" + versionTuple;
            versionsForm.appendChild(checkboxText);
            let linebreak = document.createElement("br");
            versionsForm.appendChild(linebreak);
            getEvolution(channel, version, "CERT_VALIDATION_SUCCESS_BY_CA");
            getEvolution(channel, version, "CERT_PINNING_FAILURES_BY_CA");
          }
        });
      }
    }
  });
}

function getEvolution(channel, version, metric) {
  let versionTuple = channel + "/" + version;
  Telemetry.getEvolution(channel, version, metric, {}, true, (evolutionMap) => {
    let actualEvolutionMap = evolutionMap[""];
    if (actualEvolutionMap) {
      let actualEvolutionMapSanitized = actualEvolutionMap.sanitized();
      if (actualEvolutionMapSanitized) {
        let numSubmissions = actualEvolutionMapSanitized.submissions().length;
        actualEvolutionMapSanitized.map(function(histogram, iterationIndex, date) {
          if (iterationIndex + 1 == numSubmissions) {
            setDone(versionTuple);
          }
          let millis = date.getTime();
          histogram.map(function(count, start, end, index) {
            if (index >= roots.maxBin) {
              return;
            }
            if (!entries[index]) {
              entries[index] = new Entry(roots.roots[index].label, index,
                                         roots.roots[index].sha256Fingerprint);
            }
            if (metric == "CERT_VALIDATION_SUCCESS_BY_CA") {
              if (!(versionTuple in entries[index].successCounts)) {
                entries[index].successCounts[versionTuple] = 0;
              }
              entries[index].successCounts[versionTuple] += count;
            } else if (metric == "CERT_PINNING_FAILURES_BY_CA") {
              if (!(versionTuple in entries[index].failureCounts)) {
                entries[index].failureCounts[versionTuple] = 0;
              }
              entries[index].failureCounts[versionTuple] += count;
            } else {
              throw "Unknown metric: " + metric;
            }
            if (!entries[index].successCountsByDate[millis]) {
              entries[index].successCountsByDate[millis] = {};
            }
            if (!entries[index].failureCountsByDate[millis]) {
              entries[index].failureCountsByDate[millis] = {};
            }
            if (metric == "CERT_VALIDATION_SUCCESS_BY_CA") {
              entries[index].successCountsByDate[millis][versionTuple] = count;
            } else if (metric == "CERT_PINNING_FAILURES_BY_CA") {
              entries[index].failureCountsByDate[millis][versionTuple] = count;
            }
          });
        });
      } else {
        console.error(actualEvolutionMap);
      }
    } else {
      console.error(evolutionMap);
    }
  });
}

function setDone(versionTuple) {
  let checkboxText = document.getElementById("checkboxText-" + versionTuple);
  checkboxText.removeAttribute("class");
  let notDoneYet = false;
  document.getElementById("versions").childNodes.forEach((child) => {
    if (child.getAttribute("class") == "inProgress") {
      notDoneYet = true;
    }
  });
  if (!notDoneYet) {
    updateTable();
    setSortIndicator();
  }
}

function versionIsEnabled(versionTuple) {
  let checkbox = document.getElementById("checkbox-" + versionTuple);
  return checkbox.checked;
}

function compareEntries(a, b) {
  let aVal;
  let bVal;
  if (typeof(a[sortField]) == "function") {
    aVal = a[sortField]();
    bVal = b[sortField]();
  } else {
    aVal = a[sortField];
    bVal = b[sortField];
  }
  if (aVal < bVal) {
    return -sortDirection;
  } else if (aVal == bVal) {
    return 0;
  } else {
    return sortDirection;
  }
}

let sortIndicators = {
  '-1': '\u2193',
  '1': '\u2191'
};

function setSortIndicator() {
  let th = document.getElementById(sortField + "Sort");
  let content = th.textContent;
  if (content[content.length - 1] != sortIndicators[sortDirection]) {
    th.textContent = content + sortIndicators[sortDirection];
  }
}

function unsetSortIndicator() {
  let th = document.getElementById(sortField + "Sort");
  let content = th.textContent;
  if (content[content.length - 1] == sortIndicators[sortDirection]) {
    th.textContent = content.substring(0, content.length - 1);
  }
}

function handleSortClick(event) {
  unsetSortIndicator();
  let targetSortField = event.target.id.replace(/Sort$/, '');
  if (targetSortField == sortField) {
    sortDirection = -sortDirection;
  } else {
    sortDirection = 1;
    sortField = targetSortField;
  }
  setSortIndicator();
  updateTable();
}

function populateTable() {
  let table = document.getElementById("table");
  let i = 0;
  for (let entry of entries) {
    let telemetryIDTD;
    let nameTD;
    let successCountTD;
    let failureCountTD;
    let tr = document.getElementById("tr" + i);
    if (!tr) {
      tr = document.createElement("tr");
      tr.id = "tr" + i;
      telemetryIDTD = document.createElement("td");
      nameTD = document.createElement("td");
      successCountTD = document.createElement("td");
      failureCountTD = document.createElement("td");
      tr.appendChild(telemetryIDTD);
      tr.appendChild(nameTD);
      tr.appendChild(successCountTD);
      tr.appendChild(failureCountTD);
      table.appendChild(tr);
    } else {
      telemetryIDTD = tr.childNodes[0];
      nameTD = tr.childNodes[1];
      successCountTD = tr.childNodes[2];
      failureCountTD = tr.childNodes[3];
    }
    telemetryIDTD.textContent = entry.telemetryID;
    nameTD.textContent = entry.getName();
    nameTD.onmouseover = function(entry, event) {
      doPopup(entry, event);
    }.bind(null, entry); // fun with closures
    nameTD.onmouseout = function(event) {
      clearPopup();
    };
    let successes = entry.getEnabledSuccesses();
    let failures = entry.getEnabledFailures();
    successCountTD.textContent = successes;
    failureCountTD.textContent = failures;
    tr.setAttribute("class", "");
    if (successes == 0 && failures == 0) {
      tr.setAttribute("class", "unusedCA");
    } else if (failures == 0) {
      tr.setAttribute("class", "noFailures");
    } else if (successes == 0 && failures > 0) {
      tr.setAttribute("class", "onlyFailures");
    } else if (successes > 0 && failures > 0) {
      tr.setAttribute("class", "someFailures");
    }
    tr.onclick = function(entry, event) {
      doChart(entry, event);
    }.bind(null, entry); // fun with closures
    i++;
  }
}

function clearChildren(elementId) {
  let element = document.getElementById(elementId);
  while (element.children.length > 0) {
    element.children[0].remove();
  }
}

function maybeCloseChart(evt) {
  if (evt.target == document.body) {
    clearChildren('timeseries');
  }
}

function doPopup(entry, event) {
  clearChildren("popup");
  let popup = document.getElementById("popup");
  popup.style.display = "block";
  popup.style.left = event.layerX + "px";
  popup.style.top = event.layerY + "px";
  let nameP = document.createElement("p");
  nameP.textContent = entry.name;
  popup.appendChild(nameP);
  let hashP = document.createElement("p");
  hashP.setAttribute("class", "monospace");
  hashP.textContent = entry.getHash();
  popup.appendChild(hashP);
}

function clearPopup() {
  clearChildren("popup");
  let popup = document.getElementById("popup");
  popup.style.display = "none";
}

function doChart(entry, event) {
  event.stopPropagation();
  let successData = entry.getEnabledSuccessTimeSeriesData();
  let failureData = entry.getEnabledFailureTimeSeriesData();
  new Highcharts.StockChart({
    chart: {
      renderTo: "timeseries"
    },
    legend: {
      enabled: true
    },
    series: [
      { data: successData,
        name: "Successful Verifications"
      },
      { data: failureData,
        name: "Pinning Failures"
      }
    ],
    title: {
      text: entry.getName()
    }
  });
  let timeseries = document.getElementById("timeseries");
  timeseries.style.left = event.layerX + "px";
  timeseries.style.top = event.layerY + "px";
}

function clearTable() {
  let table = document.getElementById("table");
  for (let i = 0; i < entries.length; i++) {
    let tr = document.getElementById("tr" + i);
    if (tr) {
      tr.setAttribute("class", "");
      let telemetryIDTD = tr.childNodes[0];
      telemetryIDTD.textContent = 0;
      let nameTD = tr.childNodes[1];
      nameTD.textContent = '';
      let successCountTD = tr.childNodes[2];
      successCountTD.textContent = 0;
      let failureCountTD = tr.childNodes[3];
      failureCountTD.textContent = 0;
    }
  }
}

function updateTable() {
  entries.sort(compareEntries);
  clearTable();
  populateTable();
}
