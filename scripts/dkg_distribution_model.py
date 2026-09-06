"""High-precision integer Gaussian convolution and short-share leakage checks.

This unreduced scalar model excludes commitments, hash challenges, rejection,
and adversarial contribution selection. It is not a DKG security test.
"""

from decimal import Decimal, localcontext


def weight(x, sigma):
    """Unnormalized integer Gaussian mass with standard deviation parameter sigma."""
    return (-(x * x) / (2 * sigma * sigma)).exp()


def main():
    """Check conditional densities and distinguish convolution from width rescaling."""
    with localcontext() as context:
        context.prec = 80
        points = [Decimal(k) for k in range(-40, 41)]
        comparisons = 0
        for sigma in map(Decimal, [1, 2]):
            for b in map(Decimal, range(-3, 4)):
                direct = [weight(k, sigma) * weight(k - b, sigma) for k in points]
                shifted = [(-((k - b / 2) ** 2) / sigma ** 2).exp() for k in points]
                total_direct, total_shifted = sum(direct), sum(shifted)
                assert max(abs(a / total_direct - c / total_shifted)
                           for a, c in zip(direct, shifted)) < Decimal("1e-60")
                comparisons += 1
            # A geometric bound on omitted prior mass, using normalization >= 1.
            first = Decimal(41)
            tail = 2 * weight(first, sigma) / (1 - (-(2 * first + 1) / (2 * sigma ** 2)).exp())
            assert tail < Decimal("1e-90")
        sigma = Decimal(1)
        normalized_shapes = []
        for z in map(Decimal, [0, 1]):
            convolution = sum(weight(k, sigma) * weight(z - k, sigma) for k in points)
            gaussian_shape = (-(z * z) / (4 * sigma * sigma)).exp()
            parity_factor = sum((-((k - z / 2) ** 2) / sigma ** 2).exp() for k in points)
            assert abs(convolution / gaussian_shape - parity_factor) < Decimal("1e-60")
            normalized_shapes.append(convolution / gaussian_shape)
        ratio = normalized_shapes[1] / normalized_shapes[0]
        assert abs(ratio - 1) > Decimal("1e-5")
        print(f"Integer-Gaussian conditional model: {comparisons} posterior comparisons passed.")
        print(f"Two-sample convolution odd/even shape-factor ratio (sigma=1): {ratio:.20f}")


if __name__ == "__main__":
    main()
