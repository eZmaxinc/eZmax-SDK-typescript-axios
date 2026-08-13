# EzsigntemplatesignerCreateObjectV2ResponseMPayload

Payload for POST /2/object/ezsigntemplatesigner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**a_pkiEzsigntemplatesignerID** | **Array&lt;number&gt;** | An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request. | [default to undefined]
**bEzsigntemplatepackageNeedvalidation** | **boolean** | Whether the Ezsignbulksend was automatically modified and needs a manual validation | [default to undefined]
**bEzsignbulksendNeedvalidation** | **boolean** | Whether the Ezsigntemplatepackage was automatically modified and needs a manual validation | [default to undefined]

## Example

```typescript
import { EzsigntemplatesignerCreateObjectV2ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplatesignerCreateObjectV2ResponseMPayload = {
    a_pkiEzsigntemplatesignerID,
    bEzsigntemplatepackageNeedvalidation,
    bEzsignbulksendNeedvalidation,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
