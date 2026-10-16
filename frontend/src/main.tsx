import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const root = createRoot(document.getElementById("root")!);

void import("./App").then(({ default: App }) => {
	root.render(<StrictMode><App /></StrictMode>);
}).catch((error: unknown) => {
	const message = error instanceof Error ? error.message : "Frontend configuration is unavailable.";
	root.render(<main className="center-state"><div><h1>Configuration needed.</h1><p>{message}</p><p>Add the required Vite environment variables and restart the frontend.</p></div></main>);
});
