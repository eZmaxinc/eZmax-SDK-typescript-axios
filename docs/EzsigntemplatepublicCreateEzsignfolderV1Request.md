# EzsigntemplatepublicCreateEzsignfolderV1Request

Request for POST /1/object/ezsigntemplatepublic/createEzsignfolder

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pksEzmaxcustomerCode** | **string** | The Ezmaxcustomer code | [default to undefined]
**sEzsigntemplatepublicReferenceid** | **string** | The referenceid of the Ezsigntemplatepublic | [default to undefined]
**a_sEzsigntemplatesignerDescription** | **Array&lt;string&gt;** |  | [default to undefined]
**a_objEzsignsigner** | [**Array&lt;EzsignsignerRequestCompound&gt;**](EzsignsignerRequestCompound.md) |  | [default to undefined]

## Example

```typescript
import { EzsigntemplatepublicCreateEzsignfolderV1Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplatepublicCreateEzsignfolderV1Request = {
    pksEzmaxcustomerCode,
    sEzsigntemplatepublicReferenceid,
    a_sEzsigntemplatesignerDescription,
    a_objEzsignsigner,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
