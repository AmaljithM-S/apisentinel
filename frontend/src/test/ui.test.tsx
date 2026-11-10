import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Confidence, SeverityBadge } from "../components/ui";
import Login from "../pages/Login";

describe("UI primitives", () => {
  it("renders confidence as an accessible meter", () => {
    render(<Confidence value={0.98} />);
    const meter = screen.getByRole("meter", { name: "Confidence" });
    expect(meter).toHaveAttribute("aria-valuenow", "98");
  });

  it("labels severity", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("critical")).toHaveClass("sev-critical");
  });
});

describe("Login", () => {
  it("has labelled inputs", () => {
    render(<MemoryRouter><Login /></MemoryRouter>);
    expect(screen.getByLabelText("Email")).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
  });
});
