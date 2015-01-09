const MAX_CA_NAME_LEN = 50;
function formatName(name) {
  let result = name.replace(/_/g, " ");
  if (result.length > MAX_CA_NAME_LEN) {
    result = result.substring(0, MAX_CA_NAME_LEN) + "...";
  }
  return result;
}

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

// name: the name of the CA in question
// successCounts: a map of version -> successful validation count
// failureCounts: a map of version -> pinning failure count
function Entry(name) {
  this.name = formatName(name);
  this.successCounts = {};
  this.failureCounts = {};
}

Entry.prototype = {
  name: '',
  successCounts: null,
  failureCounts: null,
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
  }
};

function initializeTelemetry() {
  Telemetry.init(function() {
    let versions = Telemetry.versions();
    for (let version of versions) {
      loadMeasures(version);
    }
  });
}

function loadMeasures(version) {
  Telemetry.measures(version, function(measures) {
    if ("CERT_VALIDATION_SUCCESS_BY_CA" in measures &&
        "CERT_PINNING_FAILURES_BY_CA" in measures) {
      let versionsForm = document.getElementById("versions");
      let checkbox = document.createElement("input");
      checkbox.id = "checkbox-" + version;
      checkbox.type = "checkbox";
      checkbox.value = version;
      checkbox.checked = true;
      versionsForm.appendChild(checkbox);
      let checkboxText = document.createTextNode(version);
      versionsForm.appendChild(checkboxText);
      let linebreak = document.createElement("br");
      versionsForm.appendChild(linebreak);
      loadData(version, "CERT_VALIDATION_SUCCESS_BY_CA");
      loadData(version, "CERT_PINNING_FAILURES_BY_CA");
    }
  });
}

function loadData(version, measure) {
  Telemetry.loadEvolutionOverBuilds(version, measure,
                                    function(histogramEvolution) {
    let histogram = histogramEvolution.range();
    histogram.each(function(count, start, end, index) {
      if (index < roots.maxBin) {
        if (!entries[index]) {
          entries[index] = new Entry(roots.roots[index].label);
        }
        if (measure == "CERT_VALIDATION_SUCCESS_BY_CA") {
          if (entries[index].successCounts[version]) {
            throw "re-setting success count?";
          }
          entries[index].successCounts[version] = count;
        } else if (measure == "CERT_PINNING_FAILURES_BY_CA") {
          if (entries[index].failureCounts[version]) {
            throw "re-setting failure count?";
          }
          entries[index].failureCounts[version] = count;
        } else {
          throw "Unknown measure: " + measure;
        }
      }
    });
    updateTable();
  });
}

function versionIsEnabled(version) {
  let checkbox = document.getElementById("checkbox-" + version);
  return checkbox.checked;
}

function populateTable() {
  let table = document.getElementById("table");
  for (let i = 0; i < entries.length; i++) {
    let successCountTD;
    let failureCountTD;
    let tr = document.getElementById("tr" + i);
    if (!tr) {
      tr = document.createElement("tr");
      tr.id = "tr" + i;
      let nameTD = document.createElement("td");
      nameTD.textContent = entries[i].name;
      successCountTD = document.createElement("td");
      failureCountTD = document.createElement("td");
      tr.appendChild(nameTD);
      tr.appendChild(successCountTD);
      tr.appendChild(failureCountTD);
      table.appendChild(tr);
    } else {
      successCountTD = tr.childNodes[1];
      failureCountTD = tr.childNodes[2];
    }
    let successes = entries[i].getEnabledSuccesses();
    let failures = entries[i].getEnabledFailures();
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
  }
}

function clearTable() {
  let table = document.getElementById("table");
  for (let i = 0; i < entries.length; i++) {
    let tr = document.getElementById("tr" + i);
    if (tr) {
      tr.setAttribute("class", "");
      let successCountTD = tr.childNodes[1];
      successCountTD.textContent = 0;
      let failureCountTD = tr.childNodes[2];
      failureCountTD.textContent = 0;
    }
  }
}

function updateTable() {
  clearTable();
  populateTable();
}
