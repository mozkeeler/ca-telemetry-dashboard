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

let sortField = "telemetryID";
let sortDirection = 1;

// name: the name of the CA in question
// successCounts: a map of version -> successful validation count
// failureCounts: a map of version -> pinning failure count
function Entry(name, id) {
  this.name = formatName(name);
  this.telemetryID = id;
  this.successCounts = {};
  this.failureCounts = {};
}

Entry.prototype = {
  name: '',
  telemetryID: -1,
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
          entries[index] = new Entry(roots.roots[index].label, index);
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
    setSortIndicator();
    updateTable();
  });
}

function versionIsEnabled(version) {
  let checkbox = document.getElementById("checkbox-" + version);
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
  for (let i = 0; i < entries.length; i++) {
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
    telemetryIDTD.textContent = entries[i].telemetryID;
    nameTD.textContent = entries[i].name;
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
