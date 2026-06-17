# EzsigndocumentGetActionableElementsForSignerV1ResponseMPayload

Payload for GET /1/object/ezsigndocument/{pkiEzsigndocumentID}/getActionableElementsForSigner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**a_objEzsignsignature** | [**Array&lt;EzsignsignatureResponseCompound&gt;**](EzsignsignatureResponseCompound.md) |  | [default to undefined]
**a_objEzsignformfieldgroup** | [**Array&lt;EzsignformfieldgroupResponseCompound&gt;**](EzsignformfieldgroupResponseCompound.md) |  | [default to undefined]

## Example

```typescript
import { EzsigndocumentGetActionableElementsForSignerV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigndocumentGetActionableElementsForSignerV1ResponseMPayload = {
    a_objEzsignsignature,
    a_objEzsignformfieldgroup,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
