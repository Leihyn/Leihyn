import { Composition } from "remotion";
import { GraveyardDemo } from "./GraveyardDemo";

export const RemotionRoot: React.FC = () => {
  return (
    <Composition
      id="GraveyardChronicles"
      component={GraveyardDemo}
      durationInFrames={30 * 60}
      fps={30}
      width={1920}
      height={1080}
    />
  );
};
