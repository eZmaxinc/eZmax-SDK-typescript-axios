# EzsigndocumentCreateEzsignelementsPositionedByWordV1Request

Request for POST /1/object/ezsigndocument/{pkiEzsigndocumentID}/createEzsignelementsPositionedByWord

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**a_objEzsignformfieldgroup** | [**Array&lt;CustomEzsignformfieldgroupCreateEzsignelementsPositionedByWordRequest&gt;**](CustomEzsignformfieldgroupCreateEzsignelementsPositionedByWordRequest.md) |  | [default to undefined]
**a_objEzsignsignature** | [**Array&lt;CustomEzsignsignatureCreateEzsignelementsPositionedByWordRequest&gt;**](CustomEzsignsignatureCreateEzsignelementsPositionedByWordRequest.md) |  | [default to undefined]

## Example

```typescript
import { EzsigndocumentCreateEzsignelementsPositionedByWordV1Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigndocumentCreateEzsignelementsPositionedByWordV1Request = {
    a_objEzsignformfieldgroup,
    a_objEzsignsignature,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
