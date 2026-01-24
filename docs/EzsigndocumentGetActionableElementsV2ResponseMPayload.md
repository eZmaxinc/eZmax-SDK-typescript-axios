# EzsigndocumentGetActionableElementsV2ResponseMPayload

Payload for GET /2/object/ezsigndocument/{pkiEzsigndocumentID}/getActionableElements

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**a_objEzsignsignature** | [**Array&lt;EzsignsignatureResponseCompound&gt;**](EzsignsignatureResponseCompound.md) |  | [default to undefined]
**a_objEzsignformfieldgroup** | [**Array&lt;EzsignformfieldgroupResponseCompound&gt;**](EzsignformfieldgroupResponseCompound.md) |  | [default to undefined]

## Example

```typescript
import { EzsigndocumentGetActionableElementsV2ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigndocumentGetActionableElementsV2ResponseMPayload = {
    a_objEzsignsignature,
    a_objEzsignformfieldgroup,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
