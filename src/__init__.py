name = "flowsynth"

try:
    from flowsynth import Model
except ImportError:
    from flowsynth.flowsynth import Model
