# EzsigntemplatedocumentpageResponse

An Ezsigntemplatedocumentpage Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigntemplatedocumentpageID** | **number** | The unique ID of the Ezsigntemplatedocumentpage | [default to undefined]
**iEzsigntemplatedocumentpageWidthimage** | **number** | The Width of the page\&#39;s image in pixels calculated at 100 DPI | [default to undefined]
**iEzsigntemplatedocumentpageHeightimage** | **number** | The Height of the page\&#39;s image in pixels calculated at 100 DPI | [default to undefined]
**iEzsigntemplatedocumentpageWidthpdf** | **number** | The Width of the page in points calculated at 72 DPI | [default to undefined]
**iEzsigntemplatedocumentpageHeightpdf** | **number** | The Height of the page in points calculated at 72 DPI | [default to undefined]
**iEzsigntemplatedocumentpagePagenumber** | **number** | The page number in the Ezsigntemplatedocument | [default to undefined]
**sComputedImageurl** | **string** | The Url to the Ezsigntemplatedocumentpage\&#39;s rasterized image.  Url will expire after 5 minutes. | [default to undefined]

## Example

```typescript
import { EzsigntemplatedocumentpageResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplatedocumentpageResponse = {
    pkiEzsigntemplatedocumentpageID,
    iEzsigntemplatedocumentpageWidthimage,
    iEzsigntemplatedocumentpageHeightimage,
    iEzsigntemplatedocumentpageWidthpdf,
    iEzsigntemplatedocumentpageHeightpdf,
    iEzsigntemplatedocumentpagePagenumber,
    sComputedImageurl,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
