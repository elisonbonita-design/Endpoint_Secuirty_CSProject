// Builds ResultsCX_Capstone_Chapters_1-3_Revised_v8.docx from the v7 text, updated to match the built system.
const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, ImageRun, Table, TableRow, TableCell, Header, AlignmentType,
  HeadingLevel, LevelFormat, PageNumber, PageBreak, WidthType, ShadingType, BorderStyle, TabStopType, Tab,
} = require("docx");

const FIG = path.join(__dirname, "fig");
const FONT = "Times New Roman";
const DOUBLE = { line: 480, before: 0, after: 0 };

// ---------- inline markup: {b}bold{/b}, {i}italic{/i}
function runs(text, base = {}) {
  const out = [];
  let b = false, i = false;
  for (const part of text.split(/(\{\/?[bi]\})/)) {
    if (part === "{b}") b = true; else if (part === "{/b}") b = false;
    else if (part === "{i}") i = true; else if (part === "{/i}") i = false;
    else if (part) out.push(new TextRun({ text: part, bold: b || base.bold, italics: i || base.italics, font: FONT, size: base.size || 24 }));
  }
  return out;
}
const P = (t) => new Paragraph({ children: runs(t), spacing: DOUBLE, indent: { firstLine: 720 } });
const PN = (t) => new Paragraph({ children: runs(t), spacing: DOUBLE });          // no indent
const C = (t, opts = {}) => new Paragraph({ children: runs(t, opts), spacing: DOUBLE, alignment: AlignmentType.CENTER });
const H1 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, children: runs(t), alignment: AlignmentType.CENTER, spacing: DOUBLE });
const H1b = (t) => new Paragraph({ children: runs(t, { bold: true }), alignment: AlignmentType.CENTER, spacing: DOUBLE });
const H2 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_2, children: runs(t), spacing: DOUBLE, keepNext: true });
const H3 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_3, children: runs(t), spacing: DOUBLE, keepNext: true });
const BUL = (t) => new Paragraph({ children: runs(t), spacing: DOUBLE, numbering: { reference: "bullets", level: 0 } });
// Objectives: top-level numbers are written out (Word restarted them when mixed with sub-levels);
// each objective's lettered list is its own numbering instance so it restarts at "a."
let objNo = 0, subNo = 0;
const NUM = (t, ref, level = 0) => {
  if (ref === "obj" && level === 0) {
    objNo += 1; subNo = 0;
    return new Paragraph({ children: [new TextRun({ text: `${objNo}.`, font: FONT, size: 24 }),
      new TextRun({ children: [new Tab()], font: FONT, size: 24 }), ...runs(t)],
      spacing: DOUBLE, indent: { left: 360, hanging: 360 }, tabStops: [{ type: TabStopType.LEFT, position: 360 }] });
  }
  if (ref === "obj") {
    const letter = String.fromCharCode(97 + subNo); subNo += 1;
    return new Paragraph({ children: [new TextRun({ text: `${letter}.`, font: FONT, size: 24 }),
      new TextRun({ children: [new Tab()], font: FONT, size: 24 }), ...runs(t)],
      spacing: DOUBLE, indent: { left: 1080, hanging: 360 }, tabStops: [{ type: TabStopType.LEFT, position: 1080 }] });
  }
  return new Paragraph({ children: runs(t), spacing: DOUBLE, numbering: { reference: ref, level } });
};
const DEF = (term, t) => new Paragraph({ children: runs(`{b}${term}.{/b} ${t}`), spacing: DOUBLE, indent: { left: 720, hanging: 720 } });
const FORMULA = (t) => new Paragraph({ children: runs(`{b}${t}{/b}`), spacing: DOUBLE, indent: { left: 360 } });
const REF = (t) => new Paragraph({ children: runs(t), spacing: DOUBLE, indent: { left: 720, hanging: 720 } });
const BREAK = () => new Paragraph({ children: [new PageBreak()] });

// ---------- figures
let figNo = 0;
function pngSize(file) {
  const b = fs.readFileSync(file);
  return { w: b.readUInt32BE(16), h: b.readUInt32BE(20), data: b };
}
function figure(file, title) {
  figNo += 1;
  const { w, h, data } = pngSize(path.join(FIG, file));
  let width = 600, height = Math.round(600 * h / w);          // 6.25 in at 96 px/in
  if (height > 790) { width = Math.round(width * 790 / height); height = 790; }
  return [
    new Paragraph({ children: runs(`{b}Figure ${figNo}{/b}`), spacing: { line: 480, before: 240 }, keepNext: true }),
    new Paragraph({ children: runs(`{i}${title}{/i}`), spacing: DOUBLE, keepNext: true }),
    new Paragraph({ children: [new ImageRun({ type: "png", data, transformation: { width, height },
      altText: { title: `Figure ${figNo}`, description: title, name: file } })],
      alignment: AlignmentType.CENTER, spacing: { after: 240 } }),
  ];
}

// ---------- tables
let tabNo = 0;
const border = { style: BorderStyle.SINGLE, size: 4, color: "000000" };
const borders = { top: border, bottom: border, left: border, right: border };
function table(title, widths, rows) {
  tabNo += 1;
  const total = widths.reduce((a, b) => a + b, 0);
  const cell = (text, i, head) => new TableCell({
    borders, width: { size: widths[i], type: WidthType.DXA },
    shading: head ? { fill: "E7E9EE", type: ShadingType.CLEAR, color: "auto" } : undefined,
    margins: { top: 40, bottom: 40, left: 90, right: 90 },
    children: [new Paragraph({ children: runs(text, { bold: head, size: 20 }), spacing: { line: 240 } })],
  });
  return [
    new Paragraph({ children: runs(`{b}Table ${tabNo}{/b}`), spacing: { line: 480, before: 240 }, keepNext: true }),
    new Paragraph({ children: runs(`{i}${title}{/i}`), spacing: DOUBLE, keepNext: true }),
    new Table({
      width: { size: total, type: WidthType.DXA }, columnWidths: widths,
      rows: rows.map((r, ri) => new TableRow({ tableHeader: ri === 0, cantSplit: true,
        children: r.map((t, i) => cell(t, i, ri === 0)) })),
    }),
    new Paragraph({ children: [], spacing: { after: 120 } }),
  ];
}

// =====================================================================================
const body = [];
const add = (...xs) => xs.flat().forEach((x) => body.push(x));

// ---------- title page
add(
  new Paragraph({ children: [], spacing: { before: 2400 } }),
  C("{b}IT SECURITY INFRASTRUCTURE AND COMPLIANCE{/b}"),
  C("{b}MONITORING SYSTEM FOR RESULTSCX{/b}"),
  PN(""),
  C("{b}Updated Chapters 1–3 (Revision 8){/b}"),
  PN(""), PN(""),
  C("Prepared by:"),
  C("[Name of Researcher 1]"), C("[Name of Researcher 2]"), C("[Name of Researcher 3]"),
  C("For review by: [Technical Adviser]"),
  C("Draft for adviser review | October 2026"),
  BREAK(),
);

// =====================================================================================
// CHAPTER 1
add(
  H1("CHAPTER 1"), H1b("THE PROBLEM AND ITS BACKGROUND"),
  H2("Introduction"),
  P("Business process outsourcing (BPO) companies in the Philippines handle large amounts of client data every day. Most of this work happens on endpoint computers, which are the laptops and desktops employees use to answer calls, process records and talk to clients. Because of this, every endpoint is a possible way in for attackers. In 2022, the Philippines ranked second among countries most attacked by web threats (Ronda, 2023), and the National Privacy Commission received 421 breach notifications in 2023, almost twice the number in the year before (ABS-CBN News, 2024)."),
  P("Attacks that reach workstations can do serious damage. When the Medusa ransomware hit PhilHealth in 2023, employee workstations were among the affected systems, and files saved on their hard drives may have been taken (Talavera & Ronda, 2023). The same pattern shows up abroad. Microsoft (2024) reported that in more than 90 percent of ransomware cases that reached the ransom stage, the attackers used devices that were not properly managed."),
  P("A basic defense is to make sure each endpoint keeps safe settings and that its drive is encrypted. These settings, however, do not stay the same forever. Updates, new software and daily use can change them without anyone noticing. Security teams need to check them on a regular basis, record what they find and confirm that problems are actually fixed. Doing all of this by hand takes time, and small changes are easy to miss."),
  P("This study proposes the IT Security Infrastructure and Compliance Monitoring System for ResultsCX. The system uses Wazuh, an open-source security platform, to check endpoint settings, watch for important security events, list installed software and open ports, find known vulnerabilities and detect changes to protected files. It also adds a check of Windows BitLocker encryption status. A web application built by the researchers then organizes the results, links each one to a requirement, ranks open findings by risk, follows every finding until it is verified and produces reports. The whole project is an academic proof of concept that will be built and tested in an isolated lab using only synthetic data."),
  H2("Background of the Study"),
  P("ResultsCX is a customer experience (CX) outsourcing company that provides customer support and related services to clients, with operations in the Philippines. [Researchers: add two or three sentences about the company here, such as when its Philippine operations started, where its sites are and what services the IT team supports.] Like other BPO companies, it relies on many employee computers to serve its clients. It is also expected to protect the personal data handled on those computers under the Data Privacy Act of 2012 and the security rules of the National Privacy Commission (NPC, 2023)."),
  P("Companies with many endpoints usually depend on tools that scan devices and report the results. Wazuh is one of these tools. Its Security Configuration Assessment (SCA) feature compares the settings of an endpoint with policy rules, many of them based on the CIS Benchmarks, and marks each check as passed, failed or not applicable (Musa, 2026). Encryption can be checked as well. BitLocker, the full-disk encryption built into Windows, is now turned on by default on many Windows 11 devices with TPM 2.0 (Sankalagere Ramesh et al., 2026), and its status can be read through the Get-BitLockerVolume command in PowerShell. Wazuh can do more than check settings. Its agent also reads Windows event logs, keeps a list of installed software and open ports, compares that software with known vulnerabilities and watches chosen files for changes. Recent studies used these features to spot failed logins, list vulnerabilities and monitor file integrity (Ahmed & Al-Ta'i, 2025; Islam & Rafique, 2024)."),
  P("Scan results alone do not finish the job, though. A list of passed and failed checks does not say which requirement each check supports, who reviewed a failed item, whether an exception was approved or whether a fix was confirmed later on. Studies that used Wazuh show that it can produce a large number of alerts, which makes these details even harder to follow (Ahmed & Al-Ta'i, 2025; Islam & Rafique, 2024). In a local study, data protection officers from BPO companies also said their compliance tools were too broad and were missing features like compliance reports and audit trails (Meneses, 2022). Without clear records, it becomes hard for an organization to prove that its safeguards are in place, which is something the NPC may ask for during compliance checks (Baker McKenzie, 2024b)."),
  P("These conditions led the researchers to build a prototype that works on top of Wazuh. Rather than creating new scanners, the system reuses the existing features of Wazuh and focuses on what happens after a result or alert comes in. The approved scope does not allow access to the systems of ResultsCX, so the prototype will be developed and tested on three laptops provided by the researchers, with synthetic endpoint names and cleaned-up requirements. Interviews with authorized IT personnel will only help decide which general monitoring needs to include."),
  H2("Objectives of the Study"),
  H3("{i}General Objective{/i}"),
  P("To design, develop, test and evaluate an IT Security Infrastructure and Compliance Monitoring System for ResultsCX that turns selected Wazuh configuration results and Windows BitLocker status into a trackable compliance workflow, built and tested as an academic proof of concept in an isolated lab."),
  H3("{i}Specific Objectives{/i}"),
  P("The study specifically aims to:"),
  NUM("Design the IT Security Infrastructure and Compliance Monitoring System, specifically:", "obj", 0),
  NUM("a physical lab network of three laptops, made up of a domain controller, a Wazuh server and a Windows test laptop, that is cut off from the internet and from ResultsCX;", "obj", 1),
  NUM("a reference network for a typical BPO site, based on public standards and simulated in Cisco Packet Tracer;", "obj", 1),
  NUM("a security configuration baseline for the Windows test laptop using Group Policy and the CIS Microsoft Windows 11 Benchmark;", "obj", 1),
  NUM("the list of monitored Windows security events, approved software and ports and protected files; and", "obj", 1),
  NUM("the system architecture, data flow, database, user roles and finding workflow of the compliance-management application.", "obj", 1),
  NUM("Develop the system with the following features:", "obj", 0),
  NUM("retrieval of selected Wazuh SCA results from the Wazuh indexer using a read-only account;", "obj", 1),
  NUM("collection of Wazuh alerts for selected Windows security events, such as audit policy changes or Microsoft Defender being turned off;", "obj", 1),
  NUM("use of the Wazuh system inventory and vulnerability detection results to flag unapproved software, unexpected open ports and known vulnerabilities;", "obj", 1),
  NUM("file integrity monitoring of a folder of synthetic client records and selected registry keys;", "obj", 1),
  NUM("collection of selected BitLocker status fields from the Windows test laptop through an authenticated PowerShell collector;", "obj", 1),
  NUM("mapping of each result or alert to a versioned requirement with a status of compliant, non-compliant, not applicable or unknown;", "obj", 1),
  NUM("a finding workflow for reviews, exceptions and simulated fixes, where a finding is marked as verified only after a later assessment confirms it;", "obj", 1),
  NUM("a rule-based risk score that ranks open findings, together with an endpoint map and a floor-plan view that show where each affected endpoint is located; and", "obj", 1),
  NUM("a dashboard with an on-demand Scan now action and compliance reports that show the status and history of each finding.", "obj", 1),
  NUM("Test the system in terms of:", "obj", 0),
  NUM("functionality of each feature, using predefined test cases;", "obj", 1),
  NUM("detection of selected security events, software and port changes, known vulnerabilities and file changes, using controlled test actions;", "obj", 1),
  NUM("accuracy in classifying known compliant and non-compliant cases;", "obj", 1),
  NUM("processing time and detection time of selected operations;", "obj", 1),
  NUM("security, including login, role permissions, collector authentication and access to Wazuh data; and", "obj", 1),
  NUM("isolation of the lab from the internet and from ResultsCX.", "obj", 1),
  NUM("Evaluate the system based on:", "obj", 0),
  NUM("test-case success rate;", "obj", 1),
  NUM("compliance-detection accuracy;", "obj", 1),
  NUM("average processing time and detection time; and", "obj", 1),
  NUM("usability ratings from the adviser and designated evaluators.", "obj", 1),
  H2("Significance of the Study"),
  P("{b}Researchers.{/b} The researchers will gain hands-on experience in connecting an existing open-source security platform to a compliance workflow they built themselves. They will also learn how to test a system using controlled test cases."),
  P("{b}IT and security practitioners.{/b} The prototype shows one way to keep endpoint findings, review records, verification history and reports in one place. It is an educational proof of concept and is not meant to take the place of enterprise security tools."),
  P("{b}ResultsCX.{/b} The company may use the prototype as a reference when thinking about how endpoint findings could be tracked and reported. Its authorized IT personnel will share only general needs during interviews, and the study will not assess the company's systems or claim to improve its actual security."),
  P("{b}Future researchers and students.{/b} Students working on similar topics may use this project as a starting point, especially for studies on Wazuh integration, encryption monitoring, compliance records and testing with synthetic data."),
  H2("Scope and Limitations of the Study"),
  H3("{i}Scope{/i}"),
  P("The study covers the design, development and testing of a compliance-management system built on top of Wazuh. All work will be done inside an isolated lab set up by the researchers. The lab uses three laptops connected through a TP-Link Archer router that is cut off from the internet: a Windows Server domain controller that applies Group Policy baselines, an Ubuntu server that runs Wazuh and the compliance web application, and a Windows 11 test laptop. The web application is written in Python with the Flask framework and keeps its records in an SQLite database. A reference network for a typical BPO site, based on public standards and not on the ResultsCX network, will also be simulated in Cisco Packet Tracer."),
  P("The system will have two user roles. An administrator manages user accounts, endpoint locations and floor plans and approves or revokes exceptions. A reviewer checks findings, records simulated fixes and prepares reports. The requirement catalogue is prepared by the researchers as a versioned file. Within this setup, the prototype will:"),
  BUL("Retrieve selected Wazuh SCA results from the Wazuh indexer in the lab using a read-only account."),
  BUL("Receive Wazuh alerts for selected Windows security events, such as audit policy changes, new user accounts and Microsoft Defender being turned off."),
  BUL("Read the system inventory and vulnerability results of the test laptop and compare them with a list of approved software and ports."),
  BUL("Watch a folder of synthetic client records and selected registry keys for added, changed or deleted items."),
  BUL("Collect selected BitLocker status fields, such as encryption percentage and protection status, from the Windows test laptop using a scheduled PowerShell collector that authenticates with a shared token."),
  BUL("Match each result or alert to a small, documented set of requirements and label it as compliant, non-compliant, not applicable or unknown."),
  BUL("Record findings, review notes, simulated exceptions, fixes and follow-up verification results, with a history of every change."),
  BUL("Rank open findings with a rule-based risk score that considers severity, other open problems on the same endpoint, the role of the endpoint, how long the finding has been open and whether it came back after a fix."),
  BUL("Show a dashboard summary, an endpoint map and a floor plan, and let a reviewer request a fresh reading of all sources with a Scan now button."),
  BUL("Generate a printable compliance report and a CSV export for the synthetic test endpoints."),
  BUL("Optionally write plain-language explanations of findings with a small language model that runs inside the lab. This feature is off by default, receives only summary data and cannot change any stored value or priority."),
  BUL("Go through functional, accuracy, processing-time, access-control, isolation and usability testing inside the lab."),
  H3("{i}Prototype Environment and Company Boundaries{/i}"),
  P("The role of ResultsCX in this study is limited to sharing general knowledge. This will be gathered through scheduled interviews with its authorized IT personnel. Topics may include general monitoring needs, common endpoint-security requirements and workflow concerns that the interviewee is allowed to discuss. Anything useful from these talks will be turned into general, cleaned-up requirements before it is used in the prototype."),
  P("Development and testing will take place on a separate lab network controlled by the researchers. This network will only hold dummy endpoint names, synthetic datasets and laptops provided by the researchers. The prototype will not be deployed in, connected to or tested against any ResultsCX environment. It will not evaluate or replace the company's existing security tools either. If a demonstration is held, it will run only in the researchers' environment."),
  H3("{i}Permitted Activities{/i}"),
  BUL("Scheduled interviews or consultations with ResultsCX IT personnel authorized to participate."),
  BUL("Discussion of general monitoring needs and workflow concerns without requesting confidential configurations or findings."),
  BUL("Development and testing using public technical documentation, sanitized requirements, synthetic data, and laptops provided by the researchers."),
  BUL("Optional review of a demonstration hosted entirely in the researchers' environment."),
  H3("{i}Activities Outside the Scope{/i}"),
  BUL("Accessing ResultsCX production, test, or development systems, databases, Active Directory, networks, VPN, cloud tenants, or endpoint devices."),
  BUL("Installing agents, scripts, or software on ResultsCX computers or conducting a pilot within company infrastructure."),
  BUL("Collecting or using real company endpoint data, hostnames, IP addresses, usernames, inventories, configuration exports, screenshots, security findings, client information, credentials, or recovery keys."),
  BUL("Publishing details about ResultsCX's actual security tools, vulnerabilities, gaps, or sensitive operating practices."),
  H3("{i}Data Protection{/i}"),
  P("Three practices guide the handling of data in this research: collect only what is needed, keep information confidential and keep the lab separate from company systems. No real ResultsCX endpoint or client information will be stored in the prototype. No assessment data will be sent to outside AI services; the optional explanation feature uses only a local model inside the lab. Interview notes will cover only general design points that the interviewee is allowed to share. The study follows the data-protection principles that apply in the country, including the security requirements in NPC Circular No. 2023-06 (NPC, 2023)."),
  H3("{i}Limitations{/i}"),
  P("The study has the following limitations:"),
  BUL("The prototype checks only a selected set of configuration items, Windows events, software, vulnerabilities and files. It does not cover every CIS Benchmark item, every Windows event or every file on the computer."),
  BUL("Only Windows endpoints are included. Linux and macOS computers, mobile devices and servers are not covered."),
  BUL("All endpoint data is synthetic or comes from laptops provided by the researchers. The results cannot show how the system would perform on real company devices or at a larger scale."),
  BUL("The encryption check reads only BitLocker status fields. It does not manage recovery keys, turn encryption on or off or prove that the data cannot be reached in other ways."),
  BUL("The system depends on the existing features of Wazuh. When Wazuh gives a wrong or missing result, the prototype can only label it as unknown or as an assessment error."),
  BUL("The Scan now button reads the latest results that Wazuh already holds. It does not make the Wazuh agent run its checks again, since Wazuh runs SCA on its own schedule and the application has no permission to send commands."),
  BUL("The system does not fix problems on its own. Fixes in the lab are simulated or done by hand, and the system only records and verifies them."),
  BUL("The risk score uses weights chosen by the researchers from public guidance. It gives an order for fixing findings in the lab and has not been validated as a measure of real business risk."),
  BUL("The optional language-model explanations can be incomplete or wrong. They are labelled as generated text, and the priority of a finding always comes from the rule-based score."),
  BUL("The application keeps its records in SQLite on a single server. This is enough for a three-laptop lab but is not designed for many users or many endpoints at the same time."),
  BUL("The usability review involves only a small number of evaluators, so its results serve as descriptive feedback and not as proof of effectiveness in a real company."),
  BUL("The project will not deploy the system at ResultsCX, perform penetration testing or vulnerability scanning or replace the security tools the company already uses."),
  BUL("The physical lab uses a home router as one flat network, so it cannot separate devices into zones. Network segmentation is shown only in the Cisco Packet Tracer reference design."),
  BUL("The Packet Tracer design is a simulation. It checks the layout and access rules but does not run Wazuh, Active Directory or the prototype."),
  BUL("The vulnerability database is loaded while the lab is still online. After the lab goes offline, it is not updated, so vulnerabilities published later will not be detected."),
  BUL("The Wazuh features for automatic response, threat hunting and cloud or container monitoring are not used, because the study is about compliance monitoring and not about responding to attacks."),
  P("Because of these limitations, all results and conclusions apply only to the documented test environment."),
  H2("Operational Definition of Terms"),
  DEF("Assessment state", "The result assigned to a check: compliant, non-compliant, not applicable, or unknown/assessment error."),
  DEF("Compliance-management layer", "The custom web application, written in Python with the Flask framework, that organizes assessment results, findings, review records, verification, risk scores and reports."),
  DEF("Domain controller", "The Windows Server computer (DC01) that runs Active Directory, DNS and Group Policy for the lab domain."),
  DEF("Encryption compliance", "Whether selected BitLocker status fields meet the encryption condition defined for a test case."),
  DEF("Endpoint", "A Windows computer checked by the system. In this study, it is the Windows 11 test laptop (WS01) in the isolated lab."),
  DEF("Evidence record", "A record connecting an assessment result to its test case, requirement, timestamp, and review or verification history."),
  DEF("File integrity monitoring (FIM)", "A Wazuh feature that takes a fingerprint (hash) of chosen files and registry keys and raises an alert when one is added, changed or deleted."),
  DEF("Finding", "A stored non-compliant or unknown result for one requirement on one endpoint, tracked until it is cleared, verified or covered by an exception."),
  DEF("Finding status", "The stage of a finding in its review: open, in review, exception, fixed pending verification, cleared or verified."),
  DEF("Group Policy Object (GPO)", "A set of Windows settings that the domain controller applies to computers in the lab domain, used here to set the security baseline of the test laptop."),
  DEF("Isolated lab", "The separate network of three laptops and a router, set up by the researchers to develop and test the prototype with no route or connection to the internet or to ResultsCX environments."),
  DEF("Reference network design", "A sample network layout for a BPO site, based on public standards and simulated in Cisco Packet Tracer, used to show where the system would fit in a real network."),
  DEF("Remediation verification", "A follow-up assessment used to check whether a previously non-compliant test condition now meets its requirement."),
  DEF("Risk score", "A number from 0 to 100, computed from fixed rules, that orders open non-compliant findings for fixing."),
  DEF("Scan now", "The dashboard action that reads the latest results from every source, re-runs the classification and verification rules and reports how many findings are new, reopened, cleared or verified."),
  DEF("Security event alert", "A Wazuh alert raised when a selected Windows event, such as an audit policy change, appears in the event logs of the test laptop."),
  DEF("Synthetic data", "Artificial endpoint labels, configurations, and results that do not identify or describe actual ResultsCX systems."),
  DEF("System inventory", "The list of installed software, open ports and running processes that the Wazuh agent collects from the test laptop."),
  DEF("Vulnerability detection", "A Wazuh feature that compares installed software with a database of known vulnerabilities (CVEs)."),
  DEF("Wazuh indexer", "The Wazuh component that stores alerts and inventory results and that the application queries with a read-only account."),
  DEF("Wazuh Security Configuration Assessment (SCA)", "Wazuh's existing feature for checking selected endpoint settings against policy rules."),
  BREAK(),
);

// =====================================================================================
// CHAPTER 2
add(
  H1("CHAPTER 2"), H1b("REVIEW OF RELATED LITERATURE AND SYSTEMS"),
  H2("Introduction"),
  P("This chapter presents local and foreign literature and studies connected to endpoint security monitoring, configuration compliance, data protection, disk encryption and the use of existing security platforms. Forty sources are reviewed in total, twenty local and twenty international. To keep the review current, all of them were published within the last five years, from 2022 to 2026. Each source is introduced first. A short summary of its main point follows, along with how it relates to the proposed IT Security Infrastructure and Compliance Monitoring System for ResultsCX. The sources include academic studies, government publications, news reports, technical guides and industry reports. Public guidance is used here as background only. The project will build a small, manageable set of checks and does not claim to meet several standards at once."),
  H2("Local Related Literature and Studies"),
  P("The local sources give the Philippine setting of the study. They cover recent attacks and breaches in the country, rules and plans from the government and research done in Philippine schools, agencies and companies."),
  P("Espiritu and Jocson (2023) reviewed news reports, government documents and studies from 2018 to 2023 to describe the state of cybersecurity in the Philippines. They listed the main laws that protect the country's digital space, among them the Cybercrime Prevention Act of 2012 and the Data Privacy Act of 2012. Malware, phishing, insider threats and the Medusa ransomware attack on PhilHealth were some of the incidents they discussed. The authors also pointed to a shortage of skilled cybersecurity workers and low public awareness. Having laws in place, based on their review, does not automatically keep an organization safe. That gap between rules and actual practice is where a monitoring tool like the proposed system can help."),
  P("Data from Kaspersky reported by Ronda (2023) placed the Philippines second among countries most attacked by web threats in 2022. The ranking was based on threats detected and blocked by Kaspersky products on users' devices, with worms and file viruses making up most of the cases. A Kaspersky official quoted in the article advised businesses to secure the endpoint first and then put encryption in place. That advice lines up with the two technical checks of the prototype, which are endpoint configuration and disk encryption status. The numbers come from one vendor's customers, so they show a trend rather than an exact count for the whole country."),
  P("In a survey reported by the Philippine News Agency (2024), 56 percent of Philippine organizations said ransomware attacks in 2023 were at least twice as frequent as in 2022. The figures came from a commissioned survey mentioned during a cybersecurity briefing, so they should be read as survey results and not as a count of every organization in the country. The report shows why being prepared matters. It does not change the scope of the capstone, which checks settings and encryption and does not detect or stop ransomware."),
  P("The Medusa ransomware attack on PhilHealth in September 2023 showed how much damage can start at the endpoint level. In their report, Talavera and Ronda (2023) wrote that the attack affected application servers and employee workstations, and that files saved on the hard drives of infected workstations may have been taken. An undersecretary of the Department of Information and Communications Technology later said that around 150 workstations had been breached. An inventory had to be done just to find out what data was exposed. Knowing the condition of each workstation ahead of time, including whether its drive is encrypted, could make that kind of follow-up faster and more certain."),
  P("The NPC received 421 breach notifications in 2023, almost double the 224 it handled in 2022, as reported by ABS-CBN News (2024). Most of the cases came from hacking, theft, phishing and unauthorized access. The privacy commissioner also said some organizations reported a breach only after it had already become public. Late reporting often happens when an organization does not know the state of its own systems. Regular, recorded checks of endpoints are one small way to close that blind spot."),
  P("NPC Circular No. 2023-06 (NPC, 2023) lists security duties for personal data held by both government and private organizations. Among them are protecting access, using secure authentication and reviewing controls from time to time. These items guided the safety features of the prototype itself, such as login, user roles and limited permissions. The researchers do not claim that the prototype certifies or fully meets the circular. The features are simply basic safeguards that fit an academic lab."),
  P("Every year, organizations covered by the Data Privacy Act must file an Annual Security Incident Report with the NPC through its Data Breach Notification Management System. According to Baker McKenzie (2024a), the report for 2023 was due on March 31, 2024, and it includes a summary of the security incidents and personal data breaches an organization encountered during the year. Producing such a summary is hard without organized records. The reporting feature of the prototype follows this idea by turning stored findings and their history into a summary that can be read and reviewed."),
  P("NPC Circular No. 2024-01, discussed by Baker McKenzie (2024b), amended the 2021 Rules of Procedure of the Commission and took effect on February 10, 2024. Aside from steps for breach investigation, it describes compliance checks the NPC may carry out, such as privacy sweeps, warning letters, requests for documents and onsite visits. Organizations should therefore be ready to show proof of their safeguards at any time. A system that keeps dated evidence for every finding helps with this kind of readiness. The prototype does this only for synthetic data, but the purpose is the same."),
  P("To guide cybersecurity work across the country, the Department of Information and Communications Technology (DICT, 2023) released the National Cybersecurity Plan 2023–2028. Its goals include stronger cyber resilience, better skills, better incident handling and active monitoring of threats to government systems. The plan works as a national roadmap. It is not a checklist for an app. What the study takes from it is the value of monitoring and of keeping records of assessments."),
  P("Department Circular No. 005, s. 2024 (DICT, 2024) sets how government offices should report cybersecurity incidents and when disclosure is required. Under the circular, incidents go through set channels instead of being shared casually. The researchers borrowed only the basic idea that a record should be easy to trace and understand. Government incident reporting is outside the scope of the prototype."),
  P("In the Philippine Development Report 2024, the Department of Economy, Planning, and Development (2025) described national efforts to build cybersecurity capability. The report also noted the change in the country's ranking in the Global Cybersecurity Index. It does not measure endpoint compliance inside private companies. Still, it shows that cybersecurity remains an open development concern in the country. This study works on one narrow piece of that concern, which is organizing configuration and encryption results so they can be reviewed."),
  P("A news release from the Presidential Communications Office (2024) reported that the DICT was investing in technology to protect the country's critical infrastructure. Stronger defenses and better threat detection were mentioned, but so was the need to focus limited resources on the most important systems. Real security work usually starts with a short list of priorities. The scope of this study was set the same way, keeping only the endpoint checks that can be built and tested with the resources available."),
  P("Blancaflor, Daluz, et al. (2023) reviewed literature on how widespread ransomware threats are in the Philippines. Their review describes the different forms of ransomware, the risks organizations face and the countermeasures that can prevent or reduce damage. The authors point out that detection deserves as much attention as prevention. Better visibility into endpoint conditions helps with both. The prototype, however, is narrow. It looks at selected settings and encryption status in a lab and does not claim to find ransomware."),
  P("Zero Trust Security was proposed by Blancaflor, Abat, et al. (2023) as a way to lower ransomware risk in the country. In this model, a user or device is not trusted automatically just because it is already inside the network. Every access has to be checked. The proposed study does not build a Zero Trust architecture. It applies a related habit on a small scale by checking endpoint conditions repeatedly and saving proof of each result."),
  P("Small and medium enterprises make up 99.58 percent of businesses in the Philippines, as noted by Blancaflor et al. (2024). Their study checked how well Philippine SMEs line up with established frameworks like NIST and ISO and proposed practical strategies that fit the limited resources of these firms. One takeaway is that a framework is only useful when it is turned into steps an organization can actually follow. The prototype applies that idea by turning a small set of requirements into checks with clear expected results instead of trying to cover an entire framework."),
  P("De Ramos and Esponilla (2022) carried out a multiple-case study of cybersecurity programs in selected state universities and colleges in the National Capital Region. Information technology personnel were interviewed. The main concerns they raised were user education, cloud security, information security strategy and unsecured personal devices. Cybersecurity in an institution is made up of many connected issues. The capstone deals with only one of them: checking the condition of endpoints and organizing what is found."),
  P("Information security in the Office of the University Registrar of the University of Southeastern Philippines was the focus of Agunod (2024). A questionnaire was answered by 150 participants. It covered the commitment of the institution, security governance, procedures and the way policies were communicated. Security, based on this study, depends on clear roles and responsibilities as much as on technical tools. That idea supports the review records and reporting features of the proposed system. The prototype will not measure an institution's overall governance, though."),
  P("Miano (2025) surveyed 308 teaching and non-teaching employees of Southern Luzon State University about their awareness of the Data Privacy Act and their data management practices. Most respondents had read and somewhat understood the law, and their data management practices were rated excellent. A strong link was found between awareness and practice. People follow rules better when they understand them. Because of this, the prototype will describe each finding in plain words so that reviewers know what was checked and why it matters."),
  P("A mixed-methods study by Arlegui (2026) explored data protection in a private school and ended with a strategic action plan. Forty-five senior high school teachers took part. The study looked at how they saw data threats, what they did to protect data and what kept them from complying. Its setting is a school and not an IT system. Even so, it deals with the same gap this project faces, which is turning a general privacy duty into something people can do every day. The prototype tries to close that gap by turning requirements into clear checks and findings."),
  P("Among the local works, the one closest to this project is Meneses (2022). The researcher built a web-based compliance management system for the Data Privacy Act aimed at business process outsourcing (BPO) companies. Data protection officers from three BPO firms were first interviewed about the systems they already used. They described these tools as too broad, hard to navigate and missing features like compliance reports, audit trails and ticketing. Sixty employees then tested the new system and rated it higher in effectiveness and efficiency than their existing ones. ResultsCX is also a BPO company. The study shows that a focused compliance tool can help, and it backs the plan of building a narrow workflow with clear reports and an audit history. Meneses focused on privacy documents, while this project focuses on technical checks on endpoints."),
  H2("International Related Literature and Studies"),
  P("The international sources cover the technical side of the project. They include security frameworks and NIST guides, studies on BitLocker, studies that used Wazuh and research on automated compliance checking. Recent global threat reports are also included to show the wider context."),
  P("The National Institute of Standards and Technology (2024) released version 2.0 of its Cybersecurity Framework. The framework groups security outcomes into six functions: Govern, Identify, Protect, Detect, Respond and Recover. Govern is new in this version and stresses that security needs clear roles, policies and oversight. Monitoring and assessment belong mostly to the Identify and Detect functions. The proposed system covers only a small part of these outcomes, mainly checking settings, recording findings and confirming fixes. Still, the framework helps explain where the project sits inside a bigger security program."),
  P("The CIS Critical Security Controls, updated to version 8.1 by the Center for Internet Security (2024), are a prioritized list of safeguards against common attacks. Two of its controls are very close to this project. One deals with keeping secure configurations of enterprise assets, and the other deals with data protection, which includes encrypting data on end-user devices. Version 8.1 also added a Govern function to match NIST CSF 2.0. The prototype will borrow sample requirements from these public controls instead of using any company configuration, and it will not claim to meet the full set."),
  P("Scarfone and Souppaya (2023) drafted an updated NIST guide on planning cybersecurity log management. It helps organizations decide how log data should be generated, sent, stored, accessed and disposed of. Good records make it possible to look back on what happened. For this reason, the prototype stores assessment timestamps, requirement identifiers and review history. It keeps only the fields needed to explain each synthetic finding, so collecting full operating system logs is not part of the plan."),
  P("How can anyone know a fix actually worked? Souppaya and Scarfone (2022) answer this in their guide on enterprise patch management. They describe patching as a process of identifying, prioritizing, acquiring, installing and verifying updates. Installing an update is not enough, since it still has to be confirmed. The prototype will not deploy patches. It applies the same rule to its own findings, where a problem is marked verified only after a later assessment shows the requirement is met."),
  P("The StopRansomware Guide from the Cybersecurity and Infrastructure Security Agency (2023) lists ways to prevent and respond to ransomware. Some of its advice has little to do with malware itself. Organizations are told to protect their logs, use centralized log management, set baselines and review security procedures regularly. These points support collecting results in one place and keeping enough evidence to see what changed. The guide will not be applied as a whole, and the prototype will not perform ransomware response."),
  P("Sankalagere Ramesh et al. (2026) surveyed eighteen years of research on BitLocker. They found that BitLocker is now turned on by default on many Windows 11 devices with TPM 2.0, and that most of the older attacks against it no longer work on these systems. Recovery keys saved to cloud accounts and weak passwords remain as the main risks. Two lessons come from this survey. Checking that encryption is on and that protection is active is useful, and recovery keys must always be treated as secrets. The prototype will read only status fields and will never collect or store recovery keys."),
  P("Jacob et al. (2023) showed that the firmware TPM on some AMD processors can be attacked to pull out its stored secrets, including BitLocker keys, when an attacker has physical access to the device for a few hours. TPM-only protection, then, is not a perfect guarantee. For this study, the finding is a reminder to be careful with claims. The prototype can show whether a test volume is encrypted and protected, but a passed check does not mean the data can never be reached."),
  P("Musa (2026) demonstrated Windows endpoint hardening with Wazuh on a Windows 11 machine checked against the CIS Microsoft Windows 11 Benchmark. The first SCA scan passed only 121 of 473 checks, or 25 percent. After a hardening script was applied, the score went up to 210 passed checks, or 44 percent, and several checks changed from failed to passed. This shows two things the prototype depends on. SCA works on a Windows endpoint, and a later scan can confirm whether a fix actually took effect."),
  P("Islam and Rafique (2024) set up Wazuh in an Oracle VirtualBox lab to improve security monitoring for the apparel industry. A Linux server ran the Wazuh manager, and a Windows 10 machine ran the agent. The system detected failed logins, listed vulnerabilities and produced automated reports. Configuration assessment was the biggest source of alerts, with 397 alarms in their test. Their setup is very close to the one planned in this study. The results also show that SCA produces many raw alerts, so a separate layer that sorts and explains them would be useful."),
  P("Ahmed and Al-Ta'i (2025) tested how well Wazuh monitors cloud services on Amazon Web Services, including an EC2 instance and file integrity. In one week, the platform produced 1,774 security alerts. The authors concluded that Wazuh gives broad monitoring at a low cost. The number of alerts also shows a practical problem. Without some way to group and review them, important results can get lost. For this reason, the proposed compliance layer focuses on a small set of mapped findings."),
  P("Chamkar et al. (2025) proposed adding machine learning techniques to Wazuh to improve how it detects threats. Their work is about detection and not compliance. It still supports a basic point of this project, which is that the raw output of Wazuh becomes more useful when another layer helps sort and interpret it. The prototype does this in a much simpler way, using requirement mapping, clear status labels and a rule-based risk score instead of machine learning."),
  P("Manzoor et al. (2024) compared four open-source SIEM solutions for small and medium enterprises using fifteen security and performance features. Wazuh had an advanced implementation of thirteen of these features. Smaller organizations often work with tight budgets, so free tools that perform well matter a lot to them. This result supports the choice of Wazuh as the base of the prototype."),
  P("Amami et al. (2024) explored several open-source SIEM tools and then deployed a solution built on Wazuh to strengthen cyber defense. They went through the same choice the researchers faced, which is picking one open platform out of many, and they also ended up with Wazuh. The proposed project uses several existing features of the platform, namely configuration assessment, event alerts, inventory, vulnerability detection and file integrity monitoring, and adds its own workflow on top of them."),
  P("Poudel (2026) built a framework that joins Wazuh, Ansible and a FastAPI orchestration layer to enforce CIS Benchmark controls on Ubuntu machines and to fix configuration drift automatically. Across 207 CIS checks, the compliance score rose from 36 percent to 83 percent. Detection took about one minute and thirty seconds on average, and fixing took about one minute and forty-five seconds. The framework also queried the Wazuh API to pull security data into a separate interface. The prototype follows a similar pattern of reading Wazuh data programmatically, in its case from the Wazuh indexer, but it records review and verification instead of changing settings automatically."),
  P("Kotenko et al. (2022) reviewed 127 publications on methods for correlating security events. They grouped the methods by technique, data source, architecture and evaluation criteria. Correlation can cut repeated alerts and connect events into sequences that make more sense. The proposed system is far simpler than a correlation engine. Still, it shares the same goal of turning raw results into something meaningful, which it does by linking every finding to a requirement and to its later verification."),
  P("Morić et al. (2026) measured the effect of automated endpoint compliance and security monitoring in Linux environments. Their modular framework combined configuration checks, endpoint validation, monitoring and central reporting. Automation reduced manual compliance work in their test setup and made assessment records more repeatable. The operating system is different, but the approach is very close to this project. Both judge an automated compliance tool by measurable results and not just by its list of features."),
  P("For its 2025 Data Breach Investigations Report, Verizon (2025) analyzed more than 22,000 security incidents and over 12,000 confirmed breaches. Ransomware, exploited vulnerabilities, stolen credentials and third-party involvement were among the patterns found, with results broken down by industry and region. The report shows why organizations need to see their own security conditions clearly. It does not prove that the prototype works. The capstone will measure its own accuracy, test success rate and processing time using controlled cases."),
  P("Thousands of publicly reported incidents were studied by the European Union Agency for Cybersecurity (2024) for its yearly threat landscape report. Ransomware, threats against data and threats against availability were among the top threats in that period. Protecting stored data on endpoints is part of the answer to these threats. This supports including encryption status as one feature of the prototype. Encryption alone cannot stop every breach or attack, and the study makes no such claim."),
  P("IBM (2025) drew on breach research for its Cost of a Data Breach Report, which covers detection, response and the business impact of breaches. The report observed that security automation helped the studied organizations find and contain breaches faster. This encouraged the researchers to measure actual operations, such as how long it takes to retrieve data and generate a report. IBM's numbers will not be applied to this system. Only results from the researchers' own lab will be reported."),
  P("In its Digital Defense Report 2024, Microsoft (2024) observed a 2.75-times increase in human-operated ransomware encounters among its customers. In more than 90 percent of the cases that reached the ransom stage, the attackers had used unmanaged devices on the network. A device that nobody checks is a device that nobody can vouch for. This finding explains why the project focuses on knowing the condition of each endpoint, even if only a few settings are checked."),
  H2("Synthesis of Related Literature and Systems"),
  P("The local literature shows that the Philippines faces real and growing threats at the endpoint level. The country ranked among the most attacked by web threats, ransomware attacks became more frequent and breach reports to the NPC almost doubled in one year. The PhilHealth incident showed how infected workstations can expose stored files. On the policy side, the NPC now expects organizations to keep security records, report incidents every year and be ready for compliance checks. Local studies in schools, SMEs and BPO companies point to the same lesson, which is that rules work only when people understand them and when existing tools are focused enough to be useful. All of this shows that the topic matters locally. None of it points to any specific security weakness in ResultsCX."),
  P("Abroad, the literature covers security frameworks, log management, patch verification, BitLocker encryption and automated compliance checking. Several recent studies have used Wazuh in virtual labs, on Windows endpoints and with CIS Benchmarks. They found it useful, but they also show that it produces a large number of raw alerts and that its scores change only when a later scan confirms a fix. Studies on BitLocker show that checking encryption status is helpful, although a passed check is not an absolute guarantee. Taken together, the sources support a prototype that reuses existing assessment tools and adds its own workflow for mapping, review, verification and reporting."),
  P("The gap that this project fills is small and practical. Past local work on compliance systems, such as the one built for BPO companies, dealt with privacy documents instead of technical checks on endpoints. Past Wazuh studies focused on detection and alerts more than on tracking each finding until it is verified. This capstone joins the two by bringing selected Wazuh results, namely configuration checks, security events, inventory, vulnerabilities and file changes, together with BitLocker status fields into one compliance layer with consistent status labels, risk-based ordering and a traceable history. It will be tested with predetermined cases and measurable results. The study does not claim that Wazuh lacks compliance features, that no other product has similar functions or that the prototype proves compliance in a real company."),
  H2("Theoretical Framework"),
  P("The study is anchored on two public frameworks, shown in Figure 1. The NIST Cybersecurity Framework 2.0 (National Institute of Standards and Technology, 2024) groups security outcomes into six functions. The prototype supports four of them. Under Govern, it keeps a versioned requirement catalogue, separates the administrator and reviewer roles, requires an administrator to approve exceptions and keeps an audit trail for every finding. Under Identify, it records endpoints and their locations, reads software and port inventory and known vulnerabilities, and ranks findings with a rule-based risk score. Under Protect, it checks the results of protective settings, the Group Policy baseline and BitLocker encryption, against defined requirements. Under Detect, it reads configuration checks, security event alerts and file integrity alerts, and lets a reviewer request a fresh reading at any time. Respond and Recover are outside the scope, since the system records and verifies fixes but does not respond to incidents."),
  P("The CIS Critical Security Controls v8.1 (Center for Internet Security, 2024) supply the content of the requirements. Control 4 covers the secure configuration of enterprise assets, and Control 3 covers data protection, including the encryption of data on end-user devices. The sample requirements in the catalogue are drawn from these controls and from the CIS Microsoft Windows 11 Benchmark used by the Wazuh SCA policy (Musa, 2026)."),
  P("Two principles from NIST guidance shape how each finding is handled. Following Souppaya and Scarfone (2022), a fix is not accepted on the word of the person who made it; it counts only after a later assessment confirms it. Following Scarfone and Souppaya (2023), each result keeps its time, requirement, catalogue version and review history, so that it can be explained later."),
  figure("f01_theory.png", "Theoretical Framework of the Study"),
  H2("Conceptual Framework"),
  P("The study follows the Input–Process–Output (IPO) model, shown in Figure 2, to explain how the system turns test inputs into organized compliance information. The inputs are the general monitoring needs that interviewees are allowed to share, a versioned requirement catalogue, Wazuh results for the Windows test laptop (configuration checks, security events, inventory, vulnerabilities and file changes), selected BitLocker status fields, synthetic asset details and the defined test cases. The process starts with preparing a simple set of cleaned-up requirements. The application then reads the Wazuh indexer with a read-only account and receives collector reports. Each result is matched to its requirement and classified into one of four states. Non-compliant and unknown results become findings, open findings are ranked with a rule-based risk score and reviewers record reviews, exceptions and simulated fixes. A finding is verified only by a later assessment, and summaries and reports are produced. The outputs are a working Wazuh-based prototype, findings with status and audit history, a prioritized fix list with an endpoint map and floor plan, a dashboard and reports, and documented test results."),
  figure("f02_ipo.png", "Input–Process–Output (IPO) Framework of the Proposed System"),
  BREAK(),
);

// =====================================================================================
// CHAPTER 3
add(
  H1("CHAPTER 3"), H1b("RESEARCH METHODOLOGY"),
  H2("Research Design"),
  P("This study uses a developmental research design. The goal is to build a working prototype and check whether its selected functions behave as planned. Instead of rebuilding a security platform, the researchers will connect the existing endpoint assessment features of Wazuh to a compliance-management layer they will develop, and then test it in a small physical lab made up of three laptops."),
  P("Quantitative descriptive methods will summarize the results of functional tests, classification accuracy and processing time. Approved reviewers who view the prototype in the researchers' environment may also fill out a structured rating form on usability. None of these measures will be used to judge the condition of ResultsCX infrastructure."),
  H2("Research Methodology"),
  P("Five activities make up the methodology: limited consultation on requirements, review of documents, prototyping, controlled testing and evaluation."),
  P("{b}Domain knowledge gathering.{/b} ResultsCX IT personnel chosen by management will be interviewed on schedule. The talks will cover only general endpoint-monitoring needs, common configuration requirements and workflow concerns that can be shared without sensitive details. The researchers will not ask for tool names, network designs, production configurations, vulnerabilities, security findings or company data. Notes will be summarized as general design points and will not be kept as technical lists."),
  P("{b}Review of literature and technical documentation.{/b} Related studies and official documentation will be reviewed, particularly for Wazuh, its SCA feature and indexer, and Windows BitLocker status reporting. A check will be included only if it can be explained and tested in the available lab. Every check will have a plain-language description, an expected result and a test method that can be repeated."),
  P("{b}Controlled data generation.{/b} Synthetic endpoint names and known test cases will be created by the researchers. Some tests will collect real status data from the Windows test laptop. Other cases, especially states that are hard to prepare safely, will use synthetic fixtures clearly marked as simulated. No data will come from any ResultsCX endpoint."),
  P("{b}Prototype integration.{/b} A domain controller will apply a Group Policy baseline to the test laptop. Wazuh will provide SCA results and alerts for selected security events, software inventory, vulnerabilities and file changes, while a custom PowerShell collector will read chosen BitLocker volume-status fields and send them with a shared token. A web application written in Python with the Flask framework will then read the Wazuh results from the Wazuh indexer, normalize the data, map it to the baseline catalogue and manage findings and reports in an SQLite database. Access to Wazuh data will require authentication and will stay inside the isolated lab."),
  H2("Project Design"),
  P("The project design covers the lab network, the parts of the system, its architecture and data flow, the user roles, the database and the finding workflow. ResultsCX cannot share its network for privacy and security reasons, so the researchers did not try to copy it. The design follows public standards instead, mainly the CIS Critical Security Controls (Center for Internet Security, 2024) and the CIS Benchmarks used by Wazuh (Musa, 2026)."),
  H3("{i}Lab Network Design{/i}"),
  P("The prototype will be built and tested on three laptops connected through a TP-Link Archer router, as shown in Figure 3. The router is not used to reach the internet. It only works as a simple switch that joins the three laptops on one private network, 10.20.0.0/24. Two laptops act as servers, and the third is the client being monitored."),
  figure("f03_lab.png", "Network Diagram of the Physical Lab Setup"),
  P("Table 1 lists the role and address of each device. All addresses are fixed, so the router's DHCP server is turned off."),
  table("Devices and IP Addresses Used in the Lab", [1900, 1900, 3760, 1800], [
    ["Device", "Operating system", "Role", "IP address"],
    ["Laptop 1 (DC01)", "Windows Server 2022", "Domain controller: Active Directory, DNS, Group Policy", "10.20.0.10"],
    ["Laptop 2 (SEC01)", "Ubuntu Server 24.04 LTS", "Wazuh server, compliance application (Flask), SQLite database", "10.20.0.20"],
    ["Laptop 3 (WS01)", "Windows 11 Pro", "Monitored client: Wazuh agent, BitLocker, status collector", "10.20.0.101"],
    ["TP-Link Archer", "Router firmware", "Joins the three laptops", "10.20.0.254"],
  ]),
  P("The laptops talk to each other in three ways. DC01 sends the Group Policy baseline to WS01 and also handles its DNS and sign-in. The Wazuh agent on WS01 checks the laptop's own settings, reads its event logs, lists its software and watches protected files, then sends all of this to SEC01 on TCP ports 1514 and 1515. A small PowerShell script on WS01 sends the BitLocker status to the application on SEC01 over HTTPS on port 8443, with a shared token that the application checks. SEC01 does not join the domain, since it only needs to be reachable at its IP address."),
  P("The lab runs in two modes. In setup mode, the router's WAN cable is plugged in only so the researchers can download installers and updates. Before any testing begins, the lab switches to lab mode. The WAN cable is unplugged, no laptop has a default gateway and Wi-Fi is turned off on all three. The router's Wi-Fi, WPS, UPnP and remote management are also turned off. Every switch between modes will be written in a lab log, and no company VPN, company network or ResultsCX system will ever be connected."),
  P("A home router cannot split a network into separate zones or apply access rules. The physical lab is therefore one flat network, which is enough for a three-device proof of concept."),
  H3("{i}Reference Network Design{/i}"),
  P("To show how the same system would fit in a real BPO site, the researchers also prepared a reference network design in Cisco Packet Tracer, shown in Figure 4. It is not a copy of the ResultsCX network. It is a sample design based on public guidance for secure network architecture and the management of network devices (Center for Internet Security, 2024)."),
  figure("f04_reference.png", "Reference Network Design Simulated in Cisco Packet Tracer"),
  P("All traffic in this design passes through one firewall, and users are placed in separate VLANs for servers, call-center agents, IT staff and guests. Agent computers can reach only the domain controller, the Wazuh server and the internet. Guests can reach only the internet. Switches accept remote management only through SSH from the IT VLAN, unused ports are shut down and access ports use port security. The highlighted devices are the same three used in the physical lab."),
  P("The reference design is a simulation. It shows the intended layout and access rules, but it does not run Wazuh, Active Directory or the prototype itself."),
  H3("{i}System Components{/i}"),
  P("The prototype has five parts:"),
  P("{b}Domain controller (DC01).{/b} Windows Server runs Active Directory, DNS and Group Policy. It applies a security baseline to the test laptop and keeps the BitLocker recovery key in Active Directory, away from the application."),
  P("{b}Monitored client (WS01).{/b} A Windows 11 Pro laptop joined to the lab domain runs the Wazuh agent and a PowerShell collector that reads selected BitLocker status fields. Only synthetic endpoint labels and approved test settings will be used."),
  P("{b}Wazuh security platform.{/b} The Wazuh server on SEC01 receives the data sent by the agent, checks it against Wazuh's rules and vulnerability database, and stores the results and alerts in the Wazuh indexer."),
  P("{b}Compliance-management application.{/b} A Flask application on SEC01 reads SCA results and selected alerts, inventory and vulnerability results from the Wazuh indexer with a read-only account. SCA results arrive as Wazuh alerts in the wazuh-alerts-4.x-* indices, while inventory and vulnerability results come from the wazuh-states-* indices. The application also receives the BitLocker status from the collector, maps each result or alert to a baseline version, ranks open findings with a rule-based risk score and keeps findings, reviews, exceptions, verification history and reports in SQLite."),
  P("{b}Reviewer interface.{/b} Users open the application in a web browser from a lab laptop and sign in. Each user has a role, administrator or reviewer, which limits what they can see and do. The interface has a dashboard, an endpoint map, a floor plan, a ranked list of findings, a printable compliance report and a Scan now button that reads all sources again on request."),
  H3("{i}System Architecture{/i}"),
  P("Figure 5 shows how the parts fit together on the three laptops. The Wazuh agent on WS01 sends its results to the Wazuh manager over an encrypted connection on TCP ports 1514 and 1515, and the manager stores them in the Wazuh indexer. The compliance application never talks to the agent. It only queries the indexer, with a read-only account, over a local connection on SEC01. The BitLocker collector sends its reports directly to the application over HTTPS. Inside the application, separate modules read the indexer, receive collector reports, classify results, synchronize findings and apply the verification rules, compute risk scores, enforce the workflow and roles and produce the dashboard and reports. All application records are kept in one SQLite database. An optional local language model can run on SEC01 to write plain-language explanations; it is off by default and receives only summary data."),
  figure("f05_architecture.png", "System Architecture of the Prototype"),
  H3("{i}Wazuh Features Used{/i}"),
  P("The prototype uses five features of Wazuh, summarized in Table 2. Each one answers a different compliance question, and each produces results that the application can turn into findings."),
  table("Wazuh Features Used in the Prototype", [1900, 2450, 2450, 2560], [
    ["Feature", "What it checks", "Example finding", "How the finding is verified"],
    ["Security Configuration Assessment (SCA)", "Settings compared with the CIS Microsoft Windows 11 Benchmark", "Minimum password length is below 14 characters", "A later SCA scan shows the check as passed"],
    ["Security event alerts", "Selected Windows events, reported within seconds", "Audit policy changed; Defender real-time protection turned off", "The setting is restored and a later SCA scan or status check confirms it"],
    ["System inventory", "Installed software, open ports and running processes", "Unapproved program installed; Remote Desktop port open", "A later inventory scan no longer shows it"],
    ["Vulnerability detection", "Installed software compared with known vulnerabilities (CVEs)", "Outdated program with a known vulnerability", "A later scan no longer lists the vulnerability after the update"],
    ["File integrity monitoring (FIM)", "A folder of synthetic client records and selected registry keys", "Protected file changed or deleted; new startup registry entry", "The change is approved as an exception or reversed, and a later check confirms it"],
  ]),
  P("Security event alerts and SCA work together. An alert shows within seconds that a setting has changed, while SCA runs on a schedule and proves whether the setting is correct. An alert can open a finding, but only a later assessment can mark it as verified."),
  P("Table 3 lists the Windows events selected for the prototype. Each event will be confirmed in the lab before testing begins."),
  table("Windows Security Events Monitored in the Prototype", [3600, 3000, 2760], [
    ["Event", "Windows log and event ID", "Related requirement"],
    ["Audit policy changed", "Security, 4719", "Audit policy baseline"],
    ["Security log cleared", "Security, 1102", "Audit logs must be kept"],
    ["New user account created", "Security, 4720", "Account management"],
    ["User added to a security-enabled local group", "Security, 4732", "Least privilege"],
    ["Failed sign-in attempts (five or more in the lookback window)", "Security, 4625", "Account lockout policy"],
    ["Real-time protection turned off", "Microsoft Defender Operational, 5001", "Antivirus must stay on"],
  ]),
  P("The vulnerability database of Wazuh is normally updated online. It will be loaded while the lab is still in setup mode, so the vulnerability results will reflect the database as of that date."),
  P("Three features of Wazuh are left out on purpose. Active response, which can block addresses or change settings automatically, goes against the rule that the system records and verifies fixes instead of making them. Threat hunting and malware analysis belong to incident response rather than compliance, and they would need real attack data that cannot be created safely. Cloud and container monitoring are not needed, since the lab has neither."),
  H3("{i}Security Configuration Baseline{/i}"),
  P("The Group Policy baseline gives the test laptop known settings that Wazuh can check. It is split into several Group Policy Objects (GPOs), summarized in Table 4. The values come from Level 1 of the CIS Microsoft Windows 11 Benchmark, the same benchmark used by the Wazuh SCA policy for Windows 11 (Musa, 2026)."),
  table("Group Policy Objects Used in the Lab", [2600, 2400, 4360], [
    ["GPO", "Purpose", "Sample settings"],
    ["Default Domain Policy", "Password and account lockout rules", "Minimum length of 14 characters; lockout after 5 failed attempts"],
    ["LAB-WS-Security-Baseline", "General security options", "Guest account disabled; screen lock after 15 minutes; NTLMv2 only"],
    ["LAB-WS-Firewall", "Windows Defender Firewall", "All profiles on; inbound blocked by default; logging enabled"],
    ["LAB-WS-Audit", "Audit policy", "Logon, account management and process creation events recorded"],
    ["LAB-WS-BitLocker", "Disk encryption rules", "XTS-AES 256-bit; TPM required; recovery key saved to Active Directory"],
    ["LAB-WS-Deploy", "Lab tools", "Trust for the application certificate; scheduled BitLocker status collector"],
  ]),
  P("Group Policy keeps re-applying these settings. Because of this, the lab can also show how a setting that drifts gets restored and then confirmed by a new assessment."),
  H3("{i}Security of the Monitoring Setup{/i}"),
  P("SEC01 holds a list of the weak spots of every monitored computer, so it needs extra protection. The researchers will apply these measures:"),
  BUL("A password will be required before any agent can register with Wazuh, so other devices cannot pose as lab computers."),
  BUL("The SEC01 firewall will accept only the ports the lab needs, and only from the lab network: TCP 1514 and 1515 for the agent and TCP 8443 for the application. The Wazuh API and the Wazuh indexer will not be open to the network."),
  BUL("The application will use a read-only account for the Wazuh indexer. It does not use the Wazuh server API and cannot send commands to agents."),
  BUL("Users sign in with a password of at least 12 characters, stored only as a salted hash. Five wrong passwords lock the account for 15 minutes, and every user has either the administrator or the reviewer role."),
  BUL("The application refuses to start on any address outside 127.0.0.1 or the lab network, and it requires TLS when it listens on the lab network."),
  BUL("The BitLocker collector must present a shared token. The application rejects any report that contains a field resembling a recovery key, password or key protector, and stores nothing from such a report."),
  BUL("Wazuh remote commands and active response will stay turned off."),
  BUL("Wazuh and the operating systems will be updated before the lab goes offline, and their versions will be recorded."),
  BUL("Traffic between the agent and the Wazuh server is encrypted by default."),
  H3("{i}Data Flow{/i}"),
  P("Figure 6 shows the system as a single process and the outside parties it exchanges data with. The Wazuh indexer supplies configuration results, event and file alerts, inventory and vulnerabilities. The collector on WS01 supplies BitLocker status reports. Reviewers send sign-ins, Scan now requests, review notes and status changes and receive the dashboard, findings and reports. Administrators also manage accounts, endpoint locations and floor plans and decide on exceptions. The optional local AI service receives only summary data and returns explanation text."),
  figure("f06_context.png", "Context Diagram of the Compliance Monitoring System"),
  P("Figure 7 breaks the system into seven processes. Process 1.0 collects results from the indexer and stores collector reports. Process 2.0 maps each result to a requirement in the catalogue and classifies it into one of the four assessment states. Process 3.0 creates, updates, clears or verifies findings and writes an audit entry for each change. Process 4.0 scores open findings using the asset records. Process 5.0 handles review notes, status changes and exception decisions. Process 6.0 builds the dashboard, the compliance report and the CSV export. Process 7.0 manages user accounts, endpoint locations and floor plans."),
  figure("f07_dfd1.png", "Level 1 Data Flow Diagram"),
  H3("{i}User Roles{/i}"),
  P("The application has two roles, shown in Figure 8 and Table 5. The administrator can do everything a reviewer can do, and also manages accounts, endpoint locations and floor plans and approves or revokes exceptions. The Wazuh indexer and the BitLocker collector act as system actors that supply data. Running Scan now always includes reading the latest results from the indexer."),
  figure("f08_usecase.png", "Use Case Diagram of the Prototype"),
  table("Permissions of Each Role", [5560, 1900, 1900], [
    ["Action", "Administrator", "Reviewer"],
    ["Sign in; view the dashboard, endpoint map and floor plan", "Yes", "Yes"],
    ["Run Scan now", "Yes", "Yes"],
    ["View finding details and history; add review notes", "Yes", "Yes"],
    ["Set a finding to in review, fixed pending or open", "Yes", "Yes"],
    ["Approve or revoke an exception", "Yes", "No"],
    ["Print the compliance report or export CSV", "Yes", "Yes"],
    ["Request a plain-language explanation (when enabled)", "Yes", "Yes"],
    ["Create, disable or change user accounts", "Yes", "No"],
    ["Manage endpoint locations, floor plans and markers", "Yes", "No"],
    ["Set a finding to cleared or verified", "No", "No"],
  ]),
  H3("{i}Database Design{/i}"),
  P("The application keeps its records in one SQLite database, shown in Figure 9. The findings table holds one row per requirement and endpoint, with its assessment state, workflow status, severity, timestamps and the catalogue version it was created under. Every change to a finding, whether made by a person or by an assessment, is written to the finding_events table, which serves as the audit trail. Risk scores are stored in a separate table so that their history is kept. User accounts store only password hashes. BitLocker reports keep only the seven status fields sent by the collector. Asset assignments, floor plans and marker positions hold the synthetic locations used by the endpoint map and floor plan. The requirement catalogue is a versioned file and not a table; each finding refers to it by requirement identifier and catalogue version."),
  figure("f09_erd.png", "Entity Relationship Diagram of the Application Database"),
  H3("{i}Baseline and Assessment Records{/i}"),
  P("A catalogue will describe every selected requirement. Each entry will have an identifier, a title, a reference or reason for the check, the assessment source, the expected condition, applicability notes, how to read the status, a severity level and remediation guidance. The baseline will carry version numbers. That way, a later rule change will not quietly change the meaning of older test results. The current catalogue, version 1.3, holds 27 synthetic requirements in 12 areas, such as password policy, audit policy, firewall, disk encryption and file integrity."),
  P("For each assessment or alert, the system will save only what it needs: the synthetic endpoint identifier, requirement identifier, baseline version, data source, observed value or alert details, normalized status, time and any evidence or workflow references. Recovery keys, passwords, file contents and unrelated endpoint details will not be collected."),
  H3("{i}Assessment States{/i}"),
  P("The custom application will use four assessment states:"),
  BUL("{b}Compliant:{/b} The observed value satisfies the defined requirement."),
  BUL("{b}Non-compliant:{/b} The observed value does not satisfy the defined requirement."),
  BUL("{b}Not applicable:{/b} The rule does not apply under its documented applicability condition."),
  BUL("{b}Unknown/assessment error:{/b} The required information could not be assessed or validated. This state will not be treated automatically as a confirmed failure. A BitLocker report older than 24 hours is also treated as unknown."),
  P("Having these four states lets the tests compare expected and actual outcomes fairly. Missing data will not be mistaken for a confirmed configuration problem. When a data source cannot be read, its findings are left unchanged and the dashboard shows a warning, so an unreadable source is never treated as fixed."),
  H3("{i}Finding Workflow{/i}"),
  P("Every non-compliant or unknown result becomes a finding that moves through six statuses, shown in Figure 10. A new failure starts as open. A reviewer or administrator can move it to in review or mark it as fixed pending verification, and a note is required when a fix is recorded. Only an administrator can approve an exception, and approving one also requires a note. Two statuses can never be set by hand. A finding becomes cleared when a later assessment passes before anyone recorded a fix, for example when Group Policy restored the setting on its own. It becomes verified only when an assessment that is newer than the recorded fix passes. If a cleared or verified finding fails again, it reopens and the repeat is counted."),
  figure("f10_lifecycle.png", "Finding Lifecycle and Status Transitions"),
  H3("{i}Risk-Based Prioritization{/i}"),
  P("Open non-compliant findings receive a risk score from 0 to 100 that sets the order in which they should be fixed. The score is the sum of the five parts in Table 6, limited to 100. A finding never earns points for its own condition; for example, a finding about Defender being off does not get the Defender bonus. Findings in the unknown state are not scored and are listed separately as needing data. The weights are kept in a versioned file, and each stored score records the weights version used."),
  table("Parts of the Rule-Based Risk Score", [2000, 1100, 6260], [
    ["Part", "Maximum", "How the points are given"],
    ["Severity", "40", "From the mapped requirement: critical 40, high 30, medium 20, low 10. A vulnerability without a requirement uses its CVSS score multiplied by 4."],
    ["Exposure", "25", "Other open problems on the same endpoint: Defender real-time protection off (+15), firewall off (+15), CVE in the known-exploited list (+25), unapproved listening port (+10)."],
    ["Asset importance", "20", "The endpoint handles client data (+12); its role is team lead or IT administrator (+8) or shared kiosk (+4)."],
    ["Time open", "10", "Two points for each day the finding has been open."],
    ["Repeat", "5", "The finding came back after it was cleared or verified."],
  ]),
  P("The score is shown in four bands: Critical (80 and above), High (60 to 79), Medium (40 to 59) and Low (below 40). The optional language model may explain a finding in plain words, but it never sets or changes the score."),
  H2("Project Development"),
  P("Development will move in stages. The first goal is to get the main workflow working. After that, the researchers will continue with further development, refinement, testing, evaluation and documentation."),
  P("{b}Stage 1: Requirements and source review.{/b} Prepare permitted interview questions, review permitted requirements and technical documentation, and define the lab boundary. Expected output: sanitized requirements notes and an initial control catalogue."),
  P("{b}Stage 2: Lab setup.{/b} Prepare the TP-Link router, install Windows Server on DC01, Ubuntu and Wazuh on SEC01 and Windows 11 Pro on WS01, apply the Group Policy baseline and switch the lab to lab mode. Build the reference network in Cisco Packet Tracer. Expected output: a working, isolated three-laptop lab and a reference design."),
  P("{b}Stage 3: Assessment integration.{/b} Confirm that SCA results, selected event alerts, inventory, vulnerability results and file changes from WS01 reach the Wazuh indexer, and that the collector sends BitLocker status to the application. Set up the selected events, the protected folder and the list of approved software and ports. Expected output: repeatable sample assessment data and alerts."),
  P("{b}Stage 4: Custom compliance layer.{/b} Implement baseline mapping, normalized states, findings, workflow records, risk scoring and initial reports in the Flask application. Expected output: a working first version of the prototype."),
  P("{b}Stage 5: Feature refinement.{/b} Improve versioning, exceptions, verification, permissions, evidence history, the endpoint map and floor plan, and reporting. Expected output: the expanded capstone system."),
  P("{b}Stage 6: Testing and evaluation.{/b} Run labeled test cases, security checks, performance measurements, and an approved reviewer assessment. Expected output: test results, documented limitations, and an evaluation summary."),
  P("{b}Stage 7: Documentation and presentation.{/b} Finalize the paper, user instructions, architecture, open-source attribution, and demonstration scenario. Expected output: capstone documentation and final-defense demonstration."),
  P("The first working version is a milestone for the prototype only. It does not mean the whole capstone is finished at that point. Optional features will be added only after the core integration, the finding workflow and the test plan are working reliably."),
  H2("Operations Procedure"),
  P("The prototype will operate through the following sequence, summarized in Figure 11:"),
  NUM("The researcher prepares a versioned security baseline from selected technical guidance and sanitized requirements. No ResultsCX configuration file or real endpoint data is imported.", "steps"),
  NUM("The researcher starts the three laptops in lab mode and confirms that they can reach each other but not the internet.", "steps"),
  NUM("DC01 applies the Group Policy baseline to WS01.", "steps"),
  NUM("The Wazuh agent on WS01 runs the SCA assessment and sends the results to the Wazuh server on SEC01.", "steps"),
  NUM("The agent also reads the selected Windows event logs, collects the system inventory and checks the protected folder and registry keys. The Wazuh server compares the inventory with its vulnerability database and raises alerts for the selected events and file changes.", "steps"),
  NUM("The PowerShell collector on WS01 reads the selected BitLocker status fields and sends them to the application over HTTPS with the shared token.", "steps"),
  NUM("When a reviewer opens the dashboard or clicks Scan now, the application reads the selected results and alerts from the Wazuh indexer with a read-only account, together with the latest BitLocker report. A source that cannot be read is skipped with a warning, and its findings are left unchanged.", "steps"),
  NUM("The compliance layer maps each result or alert to the applicable baseline version and gives it a normalized assessment state.", "steps"),
  NUM("Non-compliant results and alerts become findings with the requirement, expected condition, observed test result, severity, timestamp and recommended review action. Open non-compliant findings receive a rule-based risk score.", "steps"),
  NUM("A reviewer records a simulated review or corrective action, or an administrator approves an exception.", "steps"),
  NUM("After a correction, such as a Group Policy refresh, resuming BitLocker, removing unapproved software or restoring a file, WS01 is assessed again. A finding is marked as verified only when the new result supports it; nobody can set this status by hand.", "steps"),
  NUM("The researcher generates the dashboard view and report, then saves the test results for evaluation.", "steps"),
  P("All steps will be demonstrated using synthetic records and test machines owned by the researchers."),
  figure("f11_flow.png", "Flowchart of the Operations Procedure"),
  H2("Testing Procedure"),
  P("{b}Functional testing.{/b} Each custom function will be tested against what it is supposed to do. The list includes creating baselines and choosing versions, retrieving SCA results, submitting encryption data, handling normalized statuses, creating findings, risk scoring, recording exceptions, verification, Scan now, audit history and report generation. Automated unit and API tests will be run after every change."),
  P("{b}Integration testing.{/b} The researchers will check if the Flask application can sign in to the Wazuh indexer with its read-only account, get the right results and alerts, accept collector reports that carry a valid token, link each one to the correct test requirement and save workflow records in SQLite. Failed tests will be written down and run again after fixes."),
  P("{b}Compliance-detection testing.{/b} A labeled test set will hold known compliant and non-compliant cases for each data source. For encryption, the set will include BitLocker states that can be prepared on the test laptop plus synthetic fixtures for other states. The output of the system will be compared with the expected result decided in advance. Unknown, unavailable and not-applicable cases will be tested on their own and reported apart from the binary accuracy score."),
  P("{b}Detection testing.{/b} The researchers will carry out controlled actions on WS01 and check that each one produces the expected finding. Examples include changing the audit policy, turning off Defender real-time protection, creating a local user, installing an unapproved program, installing an older program with a known vulnerability, opening a blocked port and editing a file in the protected folder. Each action will then be reversed to check that the finding can be verified."),
  P("{b}Workflow testing.{/b} A finding should never become verified just because someone changed a status field. The researchers will confirm that verification always depends on a later assessment result or on the defined test evidence for that case. Version changes and exceptions will be checked as well."),
  P("{b}Security testing.{/b} Login, account lockout, role permissions, collector token checks, input validation, unauthorized access attempts, secret handling and the protection of records from users without permission will all be tested. The researchers will also try to register an agent without the enrollment password and to reach the Wazuh API and the Wazuh indexer from another laptop. These attempts should fail. These tests will only target the prototype."),
  P("{b}Isolation and data-protection testing.{/b} Before each test session, the researchers will confirm that the router's WAN cable is unplugged, that no laptop has a default gateway and that Wi-Fi is off on all three laptops. A connection test from WS01 to an outside address must fail. The test database and reports will also be searched for any real company information, passwords or recovery keys that may have slipped in by accident."),
  P("{b}Performance testing.{/b} Time will be recorded for defined operations, for example retrieving a result, processing a known assessment set, completing a Scan now and generating a report. Detection time will also be recorded, measured from a test action on WS01 until the matching finding appears in the application. Each measurement will be saved together with the test conditions, the number of runs and the number of endpoints."),
  P("{b}Reference design testing.{/b} In Cisco Packet Tracer, the researchers will check that agent computers cannot reach the IT VLAN, that guests cannot reach the servers and that only IT computers can open SSH sessions to the switches. These checks show that the access rules of the design work as planned in simulation."),
  H2("Evaluation Procedure"),
  P("Evaluation will start once the core functions pass initial testing. The quantitative part will use functional test results, known expected classifications and processing-time measurements. A structured checklist will show whether each required feature works as planned."),
  P("The adviser and designated evaluators may complete a usability review. ResultsCX IT personnel may join too if they agree, but they will only view a demonstration hosted in the researchers' environment. The review will focus on how clear the prototype is, how easy its workflow is and how useful its reports are. Reviewers will not be asked about the company's real configurations or its current security tools. They will also be told that all data and endpoint labels are synthetic."),
  P("Results will be summarized descriptively. Defects, unsupported checks, assessment errors and limitations will be reported next to the successful outcomes. Findings from the isolated prototype will not be applied to the security condition of ResultsCX or to all Windows environments."),
  H2("Statistical Treatment of Data"),
  P("The researchers will use descriptive statistics to summarize the test outcomes."),
  H3("{i}1. Test-Case Success Rate{/i}"),
  P("The test-case success rate measures the proportion of executed test cases that produce their predetermined expected outcomes."),
  FORMULA("Success Rate = (Successful Test Cases / Total Executed Test Cases) × 100"),
  P("A test case counts as successful when the system completes the required operation and gives the expected result. Test cases that were not run will be left out of the denominator and listed separately."),
  H3("{i}2. Compliance-Detection Accuracy{/i}"),
  P("Accuracy will be calculated for test cases with known binary compliant or non-compliant labels, across all data sources."),
  FORMULA("Accuracy = [(TP + TN) / (TP + TN + FP + FN)] × 100"),
  P("Where:"),
  BUL("{b}TP (True Positive):{/b} A known non-compliant test case correctly identified as non-compliant."),
  BUL("{b}TN (True Negative):{/b} A known compliant test case correctly identified as compliant."),
  BUL("{b}FP (False Positive):{/b} A known compliant test case incorrectly identified as non-compliant."),
  BUL("{b}FN (False Negative):{/b} A known non-compliant test case incorrectly identified as compliant."),
  P("Unknown, assessment-error and not-applicable cases will not be counted as positive or negative here. They will be reported separately."),
  H3("{i}3. Average Processing Time{/i}"),
  P("Average processing time will measure the mean duration of a defined operation across repeated test runs."),
  FORMULA("Average Processing Time = Sum of Recorded Processing Times / Number of Test Runs"),
  P("The start and end point of every timed operation will be defined beforehand. The number of runs and the test conditions will be recorded, and results will be given in seconds or another clearly stated unit. Average detection time will be calculated the same way, using the time from a test action on WS01 until the matching finding appears in the application."),
  H3("{i}4. Weighted Mean for Usability Ratings{/i}"),
  P("If a structured five-point rating scale is used, the weighted mean will summarize the reviewers' ratings."),
  FORMULA("WM = Σ(f × x) / N"),
  P("Where:"),
  BUL("{b}WM{/b} = Weighted mean."),
  BUL("{b}f{/b} = Frequency of responses for each rating."),
  BUL("{b}x{/b} = Numerical value assigned to the rating."),
  BUL("{b}N{/b} = Total number of valid responses."),
  P("The rating scale will be interpreted as follows:"),
  BUL("{b}5 — Strongly Agree:{/b} Very High"),
  BUL("{b}4 — Agree:{/b} High"),
  BUL("{b}3 — Neither Agree nor Disagree:{/b} Moderate"),
  BUL("{b}2 — Disagree:{/b} Low"),
  BUL("{b}1 — Strongly Disagree:{/b} Very Low"),
  P("If the questionnaire is used, it will ask how clear the results are, how easy the finding workflow is to follow, how useful the reports are and how usable the system is overall. The weighted mean will be shown with the number of respondents. It will be read as descriptive feedback only and not as proof that the system works in a production environment."),
  BREAK(),
);

// =====================================================================================
// REFERENCES (unchanged from revision 7)
add(
  C("{b}References{/b}"),
  REF("ABS-CBN News. (2024, May 30). {i}2023 a 'challenging time' due to data breaches, says NPC{/i}. https://www.abs-cbn.com/news/2024/5/30/2023-a-challenging-time-due-to-data-breaches-says-npc-1550"),
  REF("Agunod, L. V. S. (2024). Development of information security framework in the Office of the University Registrar of the University of Southeastern Philippines (USEP). {i}International Journal of Advances in Engineering and Management, 6{/i}(8), 40–53. https://ijaem.net/issue_dcp/Development%20of%20Information%20Security%20Framework%20in%20the%20Office%20of%20the%20University%20Registrar%20of%20the%20University%20of%20Southeastern%20Philippines%20USEP.pdf"),
  REF("Ahmed, W. S., & Al-Ta'i, Z. T. M. (2025). Analysis of Wazuh SIEM's effectiveness in cloud security monitoring. {i}Journal of Cybersecurity and Information Management, 15{/i}(1), 244–250. https://doi.org/10.54216/JCIM.150119"),
  REF("Amami, R., Charfeddine, M., & Masmoudi, S. (2024). Exploration of open source SIEM tools and deployment of an appropriate Wazuh-based solution for strengthening cyberdefense. In {i}2024 10th International Conference on Control, Decision and Information Technologies (CoDIT){/i} (pp. 2139–2145). IEEE. https://doi.org/10.1109/CoDIT62066.2024.10708476"),
  REF("Arlegui, J. A. S. (2026). Exploring the implementation of data protection in a private institution: Basis for a strategic action plan. {i}International Journal of Sustainability and Advanced Integrated Research, 2{/i}(2). https://doi.org/10.65339/ijsair.V2.I2.589"),
  REF("Baker McKenzie. (2024a, February 7). {i}Philippines: Annual Security Incident Report due on 31 March 2024{/i}. Global Compliance News. https://www.globalcompliancenews.com/2024/02/07/https-insightplus-bakermckenzie-com-bm-data-technology-philippines-annual-security-incident-report-due-on-31-march-2024_1_01182024/"),
  REF("Baker McKenzie. (2024b, March 6). {i}Philippines: National Privacy Commission amends certain provisions of its Rules of Procedure{/i}. Global Compliance News. https://www.globalcompliancenews.com/2024/03/06/https-insightplus-bakermckenzie-com-bm-data-technology-philippines-national-privacy-commission-amends-certain-provisions-of-its-rules-of-procedure_02212024/"),
  REF("Blancaflor, E. B., Abat, A. D. D., Degrano, K. M. A., Lindio, M. C. M., & Pamoso, A. D. A. (2023). Implementation of Zero Trust Security to reduce ransomware attacks in the Philippines: A literature review. {i}Journal of Advances in Information Technology, 14{/i}(5), 928–933. https://doi.org/10.12720/jait.14.5.928-933"),
  REF("Blancaflor, E. B., Daluz, J. L. C., Garcia, R. A. G., Monton, N. G. S., & Vergara, J. M. S. (2023). A literature review on the pervasiveness of ransomware threats and attacks in the Philippines. {i}Journal of Advances in Information Technology, 14{/i}(4), 630–638. https://doi.org/10.12720/jait.14.4.630-638"),
  REF("Blancaflor, E. B., Pasco, J. A. T., Tamargo, J. B., Jonson, J. A. T., & Doydoy, J. D. A. (2024). Comparative analysis and application of cybersecurity framework to Philippine small and medium enterprises (SMEs). In {i}Proceedings of the 2024 9th International Conference on Intelligent Information Technology{/i}. Association for Computing Machinery. https://doi.org/10.1145/3654522.3654565"),
  REF("Center for Internet Security. (2024). {i}CIS Critical Security Controls{/i} (Version 8.1). https://www.cisecurity.org/controls/v8-1"),
  REF("Chamkar, S. A., Zaydi, M., Maleh, Y., & Gherabi, N. (2025). Improving threat detection in Wazuh using machine learning techniques. {i}Journal of Cybersecurity and Privacy, 5{/i}(2), Article 34. https://doi.org/10.3390/jcp5020034"),
  REF("Cybersecurity and Infrastructure Security Agency. (2023). {i}#StopRansomware guide{/i}. https://www.cisa.gov/stopransomware/ransomware-guide"),
  REF("Department of Economy, Planning, and Development. (2025). {i}Philippine development report 2024{/i}. https://depdev.gov.ph/wp-content/uploads/2025/01/PDR2024.pdf"),
  REF("Department of Information and Communications Technology. (2023). {i}National cybersecurity plan 2023–2028{/i}. https://cms-cdn.e.gov.ph/DICT/pdf/NCSP-2023-2028-FINAL-DICT.pdf"),
  REF("Department of Information and Communications Technology. (2024). {i}Department Circular No. 005, s. 2024: Reporting mechanisms and mandatory disclosure of cybersecurity incidents for the government{/i}. National Administrative Register Online, University of the Philippines Law Center. https://naro.law.upd.edu.ph/issuances/5687"),
  REF("De Ramos, N. M., & Esponilla, F. D., II. (2022). Cybersecurity program for Philippine higher education institutions: A multiple-case study. {i}International Journal of Evaluation and Research in Education, 11{/i}(3), 1198–1209. https://doi.org/10.11591/ijere.v11i3.22863"),
  REF("Espiritu, P. G. G., & Jocson, J. C. (2023). Navigating cybersecurity challenges in the era of digital transformation: Threats and mitigation strategies in the Philippines. {i}International Journal of Progressive Research in Science and Engineering, 4{/i}(11), 10–23. https://journal.ijprse.com/index.php/ijprse/article/download/994/960/1610"),
  REF("European Union Agency for Cybersecurity. (2024). {i}ENISA threat landscape 2024{/i}. https://www.enisa.europa.eu/publications/enisa-threat-landscape-2024"),
  REF("IBM. (2025). {i}Cost of a data breach report 2025{/i}. https://www.ibm.com/downloads/documents/us-en/107a02e95dc8f85c"),
  REF("Islam, M. R., & Rafique, R. (2024). Wazuh SIEM for cyber security and threat mitigation in apparel industries. {i}International Journal of Engineering Materials and Manufacture, 9{/i}(4), 136–144. https://deerhillpublishing.com/index.php/ijemm/article/download/279/262/2277"),
  REF("Jacob, H. N., Werling, C., Buhren, R., & Seifert, J.-P. (2023). {i}faulTPM: Exposing AMD fTPMs' deepest secrets{/i} (arXiv:2304.14717). arXiv. https://doi.org/10.48550/arXiv.2304.14717"),
  REF("Kotenko, I., Gaifulina, D., & Zelichenok, I. (2022). Systematic literature review of security event correlation methods. {i}IEEE Access, 10{/i}, 43387–43420. https://doi.org/10.1109/ACCESS.2022.3168976"),
  REF("Manzoor, J., Waleed, A., Jamali, A. F., & Masood, A. (2024). Cybersecurity on a budget: Evaluating security and performance of open-source SIEM solutions for SMEs. {i}PLOS ONE, 19{/i}(3), Article e0301183. https://doi.org/10.1371/journal.pone.0301183"),
  REF("Meneses, F. T. K. C. (2022). A web-based data privacy compliance management system centered on the Data Privacy Act of 2012 for business process outsourcing companies. {i}International Journal of Innovative Science and Research Technology, 7{/i}(8), 72–136. https://ijisrt.com/assets/upload/files/IJISRT22AUG088_(1).pdf"),
  REF("Miano, L. C. (2025). Awareness on data privacy vis-à-vis data management practices at a state university in Quezon province: Input towards data-driven policy and manual for good governance. {i}Edelweiss Applied Science and Technology, 9{/i}(1), 302–315. https://learning-gate.com/index.php/2576-8484/article/view/4130"),
  REF("Microsoft. (2024). {i}Microsoft digital defense report 2024{/i}. https://go.microsoft.com/fwlink/?linkid=2290930"),
  REF("Morić, Z., Balković, M., & Isić, D. (2026). Evaluating the operational impact of automated endpoint compliance and security monitoring in Linux environments. {i}Journal of Cybersecurity and Privacy, 6{/i}(2), Article 61. https://doi.org/10.3390/jcp6020061"),
  REF("Musa, F. (2026, February 19). {i}Automating Windows endpoint hardening with Wazuh{/i}. Wazuh. https://wazuh.com/blog/automating-windows-endpoint-hardening-with-wazuh/"),
  REF("National Institute of Standards and Technology. (2024). {i}The NIST Cybersecurity Framework (CSF) 2.0{/i} (NIST Cybersecurity White Paper 29). https://doi.org/10.6028/NIST.CSWP.29"),
  REF("National Privacy Commission. (2023). {i}NPC Circular No. 2023-06: Security of personal data in the government and the private sector{/i}. https://privacy.gov.ph/wp-content/uploads/2024/05/2023-compendium-2.pdf"),
  REF("Philippine News Agency. (2024, January 16). {i}Ransomware attacks in PH double in 2023{/i}. https://www.pna.gov.ph/index.php/articles/1217037"),
  REF("Poudel, D. (2026). A unified automation framework for CIS benchmark compliance and real-time remediation on Ubuntu using Wazuh, Ansible and FastAPI. {i}International Journal of Innovative Science and Research Technology, 11{/i}(4), 1362–1373. https://doi.org/10.38124/ijisrt/26apr1068"),
  REF("Presidential Communications Office. (2024, February 3). {i}DICT investing in technology to protect PH's critical infrastructure vs. cybersecurity threats{/i}. https://pco.gov.ph/news_releases/dict-investing-in-technology-to-protect-phs-critical-infrastructure-vs-cybersecurity-threats/"),
  REF("Ronda, R. A. (2023, March 15). {i}'Philippines 2nd most attacked by web threats worldwide last year'{/i}. The Philippine Star. https://www.philstar.com/headlines/2023/03/15/2251710/philippines-2nd-most-attacked-web-threats-worldwide-last-year"),
  REF("Sankalagere Ramesh, V. K., Mewundi, S. V., Honnavalli, P. B., Thoreshattalli Kenchaiah, S., & Krishna Murthy, V. M. (2026). The hardware isolation gap: A systematic survey of BitLocker forensics in the TPM 2.0 era. {i}Electronics, 15{/i}(9), Article 1959. https://doi.org/10.3390/electronics15091959"),
  REF("Scarfone, K., & Souppaya, M. (2023). {i}Cybersecurity log management planning guide{/i} (NIST Special Publication 800-92 Rev. 1, Initial Public Draft). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-92r1.ipd"),
  REF("Souppaya, M., & Scarfone, K. (2022). {i}Guide to enterprise patch management planning: Preventive maintenance for technology{/i} (NIST Special Publication 800-40 Rev. 4). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-40r4"),
  REF("Talavera, C., & Ronda, R. A. (2023, October 5). {i}PhilHealth negligence eyed in data breach{/i}. The Philippine Star. https://www.philstar.com/headlines/2023/10/05/2301268/philhealth-negligence-eyed-data-breach"),
  REF("Verizon. (2025). {i}2025 data breach investigations report{/i}. https://www.verizon.com/business/resources/reports/2025-dbir-data-breach-investigations-report.pdf"),
);

// =====================================================================================
const doc = new Document({
  creator: "Capstone researchers",
  title: "IT Security Infrastructure and Compliance Monitoring System for ResultsCX — Chapters 1–3 (Revision 8)",
  styles: {
    default: { document: { run: { font: FONT, size: 24 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: 24, bold: true, color: "000000" }, paragraph: { spacing: DOUBLE, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: 24, bold: true, color: "000000" }, paragraph: { spacing: DOUBLE, outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: 24, bold: true, italics: true, color: "000000" }, paragraph: { spacing: DOUBLE, outlineLevel: 2 } },
    ],
  },
  numbering: {
    config: [
      { reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "objsub", levels: [
        { level: 0, format: LevelFormat.LOWER_LETTER, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 1080, hanging: 360 } } } },
      ] },
      { reference: "steps", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 360, hanging: 360 } } } }] },
    ],
  },
  sections: [{
    properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, bottom: 1440, left: 1440, right: 1440 } } },
    headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT,
      children: [new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 24 })] })] }) },
    children: body,
  }],
});

const out = path.join(__dirname, "ResultsCX_Capstone_Chapters_1-3_Revised_v8.docx");
Packer.toBuffer(doc).then((buf) => { fs.writeFileSync(out, buf); console.log("wrote", out, `${figNo} figures, ${tabNo} tables`); });
