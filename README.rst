=========
mptctrace
=========

mptcptrace analyze MPTCP traces

Reference
=========

If you plan to use this tool in a publication, please use the following reference:

.. code-block:: console

        @inproceedings{Hesmans:2014:TMT:2619239.2631453,
         author = {Hesmans, Benjamin and Bonaventure, Olivier},
         title = {Tracing Multipath TCP Connections},
         booktitle = {Proceedings of the 2014 ACM Conference on SIGCOMM},
         series = {SIGCOMM '14},
         year = {2014},
         isbn = {978-1-4503-2836-4},
         location = {Chicago, Illinois, USA},
         pages = {361--362},
         numpages = {2},
         url = {http://doi.acm.org/10.1145/2619239.2631453},
         doi = {10.1145/2619239.2631453},
         acmid = {2631453},
         publisher = {ACM},
         address = {New York, NY, USA},
         keywords = {Multipath TCP},
        } 


Building
========

You can build mptctrace with:

.. code-block:: console

        $ ./autogen
        $ ./configure --prefix=whatever/
        $ make
        $ make install

I you have troubles to compile it, you can contact me.

Use it
======

You need to provide a pcap trace to mptctrace with the ``-f`` option. Mptcptrace will recognize ETH and Linux cooked header, if it's something else, you can use "-o" to tell mptctrace the offset to go to the IP header.

There is manpage in the man directory.

To get started you can try the ``-s`` option that will output MPTCP sequence graph:

.. code-block:: console

        $ mptcptrace -f myDump.pcap -s

This will generate 2 xplot files for each MPTCP connection inside the trace (one to show sequences numbers from client to server (c2s) and the other to show sequences numbers from the server to the client (s2c)).

CSV output usage
================

Mptcptrace let you output information into CSV format. It's easy to reuse to plot the information, make statistics, be creative.

To get the CSV output, you can use ``-w 2`` options, and all other regular options.


.. code-block:: console

        $ mptcptrace -f myDump.pcap -s -w 2

Will output MPTCP sequence inforamtions in a CSV format.

One quick GNU plot script example can be found in ``res/scripts/gnuplot/seq_sf``

|

.. code-block:: console
        
        $ mptcptrace -f myDump.pcap -s -w 2
        $ gnuplot -e "maxsf=16" seq_sf < c2s_seq_0.csv > seq_sf.eps
        $ evince seq_sf.eps

|

.. figure:: raw/d15cbf9ba8c22b9d012e4b97ed4310347bd90c0b/res/pics/seq_sf.png 
   :width: 100 %
   :align: center
   :figwidth: 100%


The output of the example is available in ``res/pics``. This graph shows the MPTCP mappings that pass trough subflows. In red you can also see, the mappings that cause reinjections, and in green on which sublfows they have been reinjected.

You can also use use the CSV format to easely convert some ``xplot.org`` graphs, for instance, we use the ``R`` script in ``res/scripts/R/`` to translate the flight graph.

.. code-block::

        $ mptcptrace -f myDump.pcap -F 3 -w 2
        $ // prepend ts,val,met,DONT,USE,ME to c2s_flight_0.csv
        $ ./flightR c2s_flight_0.csv win.eps

The output is available in ``res/pics``.
