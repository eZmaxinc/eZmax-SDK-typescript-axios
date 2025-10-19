# CustomEzsignfoldersignerassociationstatusResponseV3

A Ezsignfoldersignerassociationstatus Object and children to create a complete structure

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fkiEzsignfoldersignerassociationID** | **number** | The unique ID of the Ezsignfoldersignerassociation | [default to undefined]
**sEzsignfoldersignerassociationstatusLastname** | **string** | The last name of the Ezsignsigner | [optional] [default to undefined]
**sEzsignfoldersignerassociationstatusFirstname** | **string** | The first name of the Ezsignsigner | [optional] [default to undefined]
**sEzsignfoldersignerassociationstatusDescriptionX** | **string** | The description of the Ezsignsigner | [optional] [default to undefined]
**a_objEzsignsignaturestatus** | [**Array&lt;CustomEzsignsignaturestatusResponse&gt;**](CustomEzsignsignaturestatusResponse.md) |  | [default to undefined]

## Example

```typescript
import { CustomEzsignfoldersignerassociationstatusResponseV3 } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomEzsignfoldersignerassociationstatusResponseV3 = {
    fkiEzsignfoldersignerassociationID,
    sEzsignfoldersignerassociationstatusLastname,
    sEzsignfoldersignerassociationstatusFirstname,
    sEzsignfoldersignerassociationstatusDescriptionX,
    a_objEzsignsignaturestatus,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
