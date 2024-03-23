osmo-bsc - Osmocom BSC Implementation
=====================================

This repository contains a C-language implementation of a GSM Base Station
Controller (BSC).  It is part of the
[Osmocom](https://osmocom.org/) Open Source Mobile Communications
project.

OsmoBSC exposes

 * *A over IP* towards an MSC (e.g. [osmo-msc](https://osmocom.org/projects/osmomsc/wiki)): 3GPP AoIP or SCCPlite
 * *Abis* interfaces towards various kinds of BTS (e.g. [osmo-bts](https://osmocom.org/projects/osmobts/wiki/Wiki), sysmobts, nanoBTS, Siemens, Nokia, Ericsson)
 * The Osmocom typical telnet *VTY* and *CTRL* interfaces.
 * The Osmocom typical *statsd* exporter.
 * Cell Broadcast Service Protocol (*CBSP*) towards a CBC (Cell Broadcast Centre, such as [osmo-cbc](https://osmocom.org/projects/osmo-cbc/wiki)).
 * Lb interface towards a *SMLC* (Serving Mobile Location Centre, such as [osmo-smlc](https://osmocom.org/projects/osmo-smlc/wiki/OsmoSMLC)).


Homepage
--------

You can find the OsmoBSC homepage with issue tracker and wiki online at
<https://osmocom.org/projects/osmobsc/wiki>.


GIT Repository
--------------

You can clone from the official osmo-bsc.git repository using

        git clone https://gitea.osmocom.org/cellular-infrastructure/osmo-bsc

There is a web interface at <https://gitea.osmocom.org/cellular-infrastructure/osmo-bsc>


Documentation
-------------

User Manuals and VTY reference manuals are [optionally] built in PDF form
as part of the build process.

Pre-rendered PDF version of the current "master" can be found at
[User Manual](https://ftp.osmocom.org/docs/latest/osmobsc-usermanual.pdf)
as well as the [VTY Reference Manual](https://ftp.osmocom.org/docs/latest/osmobsc-vty-reference.pdf)

There also is an
[Abis reference Manual](https://ftp.osmocom.org/docs/latest/osmobts-abis.pdf)
describing the OsmoBTS specific A-bis dialect, as well as a [CBSP Reference
Maunal](https://downloads.osmocom.org/docs/latest/osmobsc-cbsp.pdf)
describing the level of CBSP conformance.


Mailing List
------------

Discussions related to osmo-bsc are happening on the
openbsc@lists.osmocom.org mailing list, please see
<https://lists.osmocom.org/mailman/listinfo/openbsc> for subscription
options and the list archive.

Please observe the [Osmocom Mailing List
Rules](https://osmocom.org/projects/cellular-infrastructure/wiki/Mailing_List_Rules)
when posting.

Contributing
------------

Our coding standards are described at
<https://osmocom.org/projects/cellular-infrastructure/wiki/Coding_standards>

We us a gerrit based patch submission/review process for managing
contributions.  Please see
<https://osmocom.org/projects/cellular-infrastructure/wiki/Gerrit> for
more details

The current patch queue for osmo-bsc can be seen at
<https://gerrit.osmocom.org/#/q/project:osmo-bsc+status:open>


History
-------

OsmoBSC originated from the OpenBSC project, which started as a minimalistic
all-in-one implementation of the GSM Network. In 2017, OpenBSC had reached
maturity and diversity (including M3UA SIGTRAN and 3G support in the form of
IuCS and IuPS interfaces) that naturally lead to a separation of the all-in-one
approach to fully independent separate programs as in typical GSM networks.

OsmoBSC was one of the parts split off from the old openbsc.git. Before, it
worked as a standalone osmo-bsc binary as well as a combination of libbsc and
libmsc, i.e. the old OsmoNITB. Since the standalone OsmoMSC with a true A
interface (and IuCS for 3G support) is available, OsmoBSC exists only as a
separate standalone entity.
