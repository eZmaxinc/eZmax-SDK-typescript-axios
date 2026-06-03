# EzdoctemplatedocumentRequestCompound

A Ezdoctemplatedocument Object and children

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzdoctemplatedocumentID** | **number** | The unique ID of the Ezdoctemplatedocument | [optional] [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**fkiEzsignfoldertypeID** | **number** | The unique ID of the Ezsignfoldertype. | [optional] [default to undefined]
**fkiEzdoctemplatetypeID** | **number** | The unique ID of the Ezdoctemplatetype | [default to undefined]
**fkiEzdoctemplatefieldtypecategoryID** | **number** | The unique ID of the Ezdoctemplatefieldtypecategory | [optional] [default to undefined]
**eEzdoctemplatedocumentPrivacylevel** | [**FieldEEzdoctemplatedocumentPrivacylevel**](FieldEEzdoctemplatedocumentPrivacylevel.md) |  | [optional] [default to undefined]
**bEzdoctemplatedocumentIsactive** | **boolean** | Whether the ezdoctemplatedocument is active or not | [default to undefined]
**objEzdoctemplatedocumentName** | [**MultilingualEzdoctemplatedocumentName**](MultilingualEzdoctemplatedocumentName.md) |  | [default to undefined]

## Example

```typescript
import { EzdoctemplatedocumentRequestCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzdoctemplatedocumentRequestCompound = {
    pkiEzdoctemplatedocumentID,
    fkiLanguageID,
    fkiEzsignfoldertypeID,
    fkiEzdoctemplatetypeID,
    fkiEzdoctemplatefieldtypecategoryID,
    eEzdoctemplatedocumentPrivacylevel,
    bEzdoctemplatedocumentIsactive,
    objEzdoctemplatedocumentName,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
