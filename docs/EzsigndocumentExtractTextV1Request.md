# EzsigndocumentExtractTextV1Request

Request for POST /1/object/ezsigndocument/{pkiEzsigndocumentID}/extractText

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**iPage** | **number** | The page where the area is located | [default to undefined]
**eSection** | **string** | The section of the page | [optional] [default to undefined]
**iX** | **number** | The X coordinate (Horizontal). Require when eSection &#x3D; \&#39;Region\&#39; or eSection is not set. | [optional] [default to undefined]
**iY** | **number** | The Y coordinate (Vertical). Require when eSection &#x3D; \&#39;Region\&#39; or eSection is not set. | [optional] [default to undefined]
**iWidth** | **number** | Area\&#39;s width. Require when eSection &#x3D; \&#39;Region\&#39; or eSection is not set. | [optional] [default to undefined]
**iHeight** | **number** | Area\&#39;s height. Require when eSection &#x3D; \&#39;Region\&#39; or eSection is not set. | [optional] [default to undefined]

## Example

```typescript
import { EzsigndocumentExtractTextV1Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigndocumentExtractTextV1Request = {
    iPage,
    eSection,
    iX,
    iY,
    iWidth,
    iHeight,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
