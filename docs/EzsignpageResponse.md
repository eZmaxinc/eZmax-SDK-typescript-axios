# EzsignpageResponse

An Ezsignpage Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignpageID** | **number** | The unique ID of the Ezsignpage | [default to undefined]
**iEzsignpageWidthimage** | **number** | The Width of the page\&#39;s image in pixels calculated at 100 DPI | [default to undefined]
**iEzsignpageHeightimage** | **number** | The Height of the page\&#39;s image in pixels calculated at 100 DPI | [default to undefined]
**iEzsignpageWidthpdf** | **number** | The Width of the page in points calculated at 72 DPI | [default to undefined]
**iEzsignpageHeightpdf** | **number** | The Height of the page in points calculated at 72 DPI | [default to undefined]
**iEzsignpagePagenumber** | **number** | The page number in the Ezsigndocument | [default to undefined]
**sComputedImageurl** | **string** | The Url to the Ezsignpage\&#39;s rasterized image.  Url will expire after 5 minutes. | [default to undefined]

## Example

```typescript
import { EzsignpageResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignpageResponse = {
    pkiEzsignpageID,
    iEzsignpageWidthimage,
    iEzsignpageHeightimage,
    iEzsignpageWidthpdf,
    iEzsignpageHeightpdf,
    iEzsignpagePagenumber,
    sComputedImageurl,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
