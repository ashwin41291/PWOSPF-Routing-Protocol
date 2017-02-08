SOFTWARE ROUTER-PHASE 2:

WORKING:
The pwospf routing protocol seems to be working fine with all the expected results. We have handled all the race conditions and made sure there is no conflict of lookups and editing at the same time, using lock conditions.
The ping(to and between servers), traceroute and wget to both the servers seems to be working in all the scenarios as you mentioned in the ‘Required Functionality’ of the document.

RESULTS:
1. When the router is first started:
	The routing table is converged after a short period of time, say one minute or less.
a. ping to both the servers - works fine.
b. wget to both the servers fetches the webpage - works fine.
c. traceroute to both the servers show the shortest path to the destination - Works fine
d. ping between servers - works fine.

2. When the link between vhost1 - vhost2 or vhost1 - vhost3 is brought down:
	The routing table is formed again after the neighbor timeout seconds.
a. ping - works fine.
b. wget - works fine.
c. traceroute to both servers - shows the shortest path - works fine.
d. ping between servers - works fine.

3. When the link is brought back:
	Some time is given for routing convergence and the routing table is formed.
a. ping - works fine.
b. wget - works fine.
c. traceroute to both servers - shows the shortest path - works fine.
d. ping between servers - works fine.


