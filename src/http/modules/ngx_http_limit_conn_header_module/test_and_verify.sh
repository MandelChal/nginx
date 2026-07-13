#!/bin/bash

# 1. Compile the NGINX source code with the custom module
make

# 2. Install the newly compiled NGINX binary
sudo make install

# 3. Force stop any running NGINX process to avoid conflicts
sudo pkill -9 nginx

# 4. Start NGINX with your custom configuration file
sudo /usr/local/nginx/sbin/nginx -c /home/ser/nginx/conf/nginx.conf

# 5. Send a single request with the required header to verify successful connection
curl -i -H "X-API-Key: Michal" http://localhost/

# 6. Send a request without headers to check the fallback/denial mechanism
curl -I http://localhost/

# 7. Clear the access log to have a clean slate for stress testing
sudo truncate -s 0 /usr/local/nginx/logs/access.log

# 8. Run a load test with 10 concurrent connections to trigger the limit
wrk -t1 -c10 -d5s -H "X-API-Key: Michal" http://localhost/

# 9. Analyze log results: Count occurrences of each HTTP status code
awk '{print $9}' /usr/local/nginx/logs/access.log | sort | uniq -c

# 10. Display real-time error logs to monitor your custom MICHAL_LOG messages
tail -f /usr/local/nginx/logs/error.log | grep "MICHAL_LOG"

# 11. Search for specific debug patterns in the error log
grep "MICHAL_LOG" /usr/local/nginx/logs/error.log | grep -E "NEW|incremented|EXCEEDED"