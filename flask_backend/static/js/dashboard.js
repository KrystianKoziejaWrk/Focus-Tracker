document.addEventListener("DOMContentLoaded", function () {
    console.log("Dashboard Loaded");
    const ctx = document.getElementById("focusChart").getContext("2d");

    fetch("/chart_data")
        .then(response => response.json())
        .then(data => {
            console.log("DEBUG: Chart data received:", data);

            // Convert labels to day names
            const labels = data.labels.map(dateStr => {
                const date = new Date(dateStr);
                console.log(`DEBUG: Converting ${dateStr} to ${date.toLocaleDateString('en-US', { weekday: 'long' })}`);
                return date.toLocaleDateString('en-US', { weekday: 'long' });
            });

            // Convert durations from seconds to hours
            const durations = data.data.map(duration => {
                console.log(`DEBUG: Duration in seconds: ${duration}, converted to hours: ${duration / 3600}`);
                return duration / 3600; // Convert seconds to hours
            });

            console.log("DEBUG: Final labels:", labels);
            console.log("DEBUG: Final durations:", durations);

            // Determine the maximum value in the durations array
            const maxDuration = Math.max(...durations);
            console.log(`DEBUG: Maximum duration: ${maxDuration}`);

            const chart = new Chart(ctx, {
                type: "line",
                data: {
                    labels: labels,
                    datasets: [{
                        label: "Focus Time (hours)",
                        data: durations,
                        borderColor: "rgba(75, 192, 192, 1)",
                        backgroundColor: "rgba(75, 192, 192, 0.2)",
                        fill: true,
                        tension: 0.1
                    }]
                },
                options: {
                    plugins: {
                        legend: {
                            display: false // Disable legend to prevent clicking on the title
                        }
                    },
                    scales: {
                        x: {
                            title: {
                                display: true,
                                text: "Day of the Week"
                            }
                        },
                        y: {
                            title: {
                                display: true,
                                text: "Focus Time (hours)"
                            },
                            min: 0,
                            suggestedMax: Math.max(8, maxDuration) // Default to 8, but adjust if maxDuration exceeds 8
                        }
                    }
                }
            });
        })
        .catch(error => console.error("Error fetching chart data:", error));
});