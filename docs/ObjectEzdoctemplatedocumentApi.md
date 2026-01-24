# ObjectEzdoctemplatedocumentApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezdoctemplatedocumentCreateObjectV1**](#ezdoctemplatedocumentcreateobjectv1) | **POST** /1/object/ezdoctemplatedocument | Create a new Ezdoctemplatedocument|
|[**ezdoctemplatedocumentDownloadV1**](#ezdoctemplatedocumentdownloadv1) | **GET** /1/object/ezdoctemplatedocument/{pkiEzdoctemplatedocumentID}/download | Retrieve the content|
|[**ezdoctemplatedocumentEditObjectV1**](#ezdoctemplatedocumenteditobjectv1) | **PUT** /1/object/ezdoctemplatedocument/{pkiEzdoctemplatedocumentID} | Edit an existing Ezdoctemplatedocument|
|[**ezdoctemplatedocumentGetAutocompleteV2**](#ezdoctemplatedocumentgetautocompletev2) | **GET** /2/object/ezdoctemplatedocument/getAutocomplete/{sSelector} | Retrieve Ezdoctemplatedocuments and IDs|
|[**ezdoctemplatedocumentGetListV1**](#ezdoctemplatedocumentgetlistv1) | **GET** /1/object/ezdoctemplatedocument/getList | Retrieve Ezdoctemplatedocument list|
|[**ezdoctemplatedocumentGetObjectV2**](#ezdoctemplatedocumentgetobjectv2) | **GET** /2/object/ezdoctemplatedocument/{pkiEzdoctemplatedocumentID} | Retrieve an existing Ezdoctemplatedocument|
|[**ezdoctemplatedocumentPatchObjectV1**](#ezdoctemplatedocumentpatchobjectv1) | **PATCH** /1/object/ezdoctemplatedocument/{pkiEzdoctemplatedocumentID} | Patch an existing Ezdoctemplatedocument|

# **ezdoctemplatedocumentCreateObjectV1**
> EzdoctemplatedocumentCreateObjectV1Response ezdoctemplatedocumentCreateObjectV1(ezdoctemplatedocumentCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzdoctemplatedocumentApi,
    Configuration,
    EzdoctemplatedocumentCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzdoctemplatedocumentApi(configuration);

let ezdoctemplatedocumentCreateObjectV1Request: EzdoctemplatedocumentCreateObjectV1Request; //

const { status, data } = await apiInstance.ezdoctemplatedocumentCreateObjectV1(
    ezdoctemplatedocumentCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezdoctemplatedocumentCreateObjectV1Request** | **EzdoctemplatedocumentCreateObjectV1Request**|  | |


### Return type

**EzdoctemplatedocumentCreateObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezdoctemplatedocumentDownloadV1**
> ezdoctemplatedocumentDownloadV1()

Using this endpoint, you can retrieve the content of an ezdoctemplatedocument.

### Example

```typescript
import {
    ObjectEzdoctemplatedocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzdoctemplatedocumentApi(configuration);

let pkiEzdoctemplatedocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezdoctemplatedocumentDownloadV1(
    pkiEzdoctemplatedocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzdoctemplatedocumentID** | [**number**] |  | defaults to undefined|


### Return type

void (empty response body)

### Authorization

[Authorization](../README.md#Authorization), [Presigned](../README.md#Presigned)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**302** | The user has been redirected |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezdoctemplatedocumentEditObjectV1**
> EzdoctemplatedocumentEditObjectV1Response ezdoctemplatedocumentEditObjectV1(ezdoctemplatedocumentEditObjectV1Request)



### Example

```typescript
import {
    ObjectEzdoctemplatedocumentApi,
    Configuration,
    EzdoctemplatedocumentEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzdoctemplatedocumentApi(configuration);

let pkiEzdoctemplatedocumentID: number; //The unique ID of the Ezdoctemplatedocument (default to undefined)
let ezdoctemplatedocumentEditObjectV1Request: EzdoctemplatedocumentEditObjectV1Request; //

const { status, data } = await apiInstance.ezdoctemplatedocumentEditObjectV1(
    pkiEzdoctemplatedocumentID,
    ezdoctemplatedocumentEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezdoctemplatedocumentEditObjectV1Request** | **EzdoctemplatedocumentEditObjectV1Request**|  | |
| **pkiEzdoctemplatedocumentID** | [**number**] | The unique ID of the Ezdoctemplatedocument | defaults to undefined|


### Return type

**EzdoctemplatedocumentEditObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezdoctemplatedocumentGetAutocompleteV2**
> EzdoctemplatedocumentGetAutocompleteV2Response ezdoctemplatedocumentGetAutocompleteV2()

Get the list of Ezdoctemplatedocument to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectEzdoctemplatedocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzdoctemplatedocumentApi(configuration);

let sSelector: 'All' | 'Ezsignfolder' | 'Ezsignfoldersignerassociations'; //The type of Ezdoctemplatedocuments to return (default to undefined)
let eType: 'User' | 'Company' | 'Ezsignfoldertype' | 'CompanyUser' | 'CompanyEzsignfoldertype'; //The type of Ezdoctemplatedocument (default to 'CompanyEzsignfoldertype')
let fkiEzsignfoldertypeID: string; //Specify which fkiEzsignfoldertypeID we want to display. only used when eType = Ezsignfoldertype (optional) (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.ezdoctemplatedocumentGetAutocompleteV2(
    sSelector,
    eType,
    fkiEzsignfoldertypeID,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39; | &#39;Ezsignfolder&#39; | &#39;Ezsignfoldersignerassociations&#39;**]**Array<&#39;All&#39; &#124; &#39;Ezsignfolder&#39; &#124; &#39;Ezsignfoldersignerassociations&#39;>** | The type of Ezdoctemplatedocuments to return | defaults to undefined|
| **eType** | [**&#39;User&#39; | &#39;Company&#39; | &#39;Ezsignfoldertype&#39; | &#39;CompanyUser&#39; | &#39;CompanyEzsignfoldertype&#39;**]**Array<&#39;User&#39; &#124; &#39;Company&#39; &#124; &#39;Ezsignfoldertype&#39; &#124; &#39;CompanyUser&#39; &#124; &#39;CompanyEzsignfoldertype&#39;>** | The type of Ezdoctemplatedocument | defaults to 'CompanyEzsignfoldertype'|
| **fkiEzsignfoldertypeID** | [**string**] | Specify which fkiEzsignfoldertypeID we want to display. only used when eType &#x3D; Ezsignfoldertype | (optional) defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**EzdoctemplatedocumentGetAutocompleteV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezdoctemplatedocumentGetListV1**
> EzdoctemplatedocumentGetListV1Response ezdoctemplatedocumentGetListV1()



### Example

```typescript
import {
    ObjectEzdoctemplatedocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzdoctemplatedocumentApi(configuration);

let eOrderBy: 'pkiEzdoctemplatedocumentID_ASC' | 'pkiEzdoctemplatedocumentID_DESC' | 'fkiLanguageID_ASC' | 'fkiLanguageID_DESC' | 'fkiEzdoctemplatetypeID_ASC' | 'fkiEzdoctemplatetypeID_DESC' | 'fkiEzdoctemplatefieldtypecategoryID_ASC' | 'fkiEzdoctemplatefieldtypecategoryID_DESC' | 'bEzdoctemplatedocumentIsactive_ASC' | 'bEzdoctemplatedocumentIsactive_DESC' | 'sEzdoctemplatedocumentNameX_ASC' | 'sEzdoctemplatedocumentNameX_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.ezdoctemplatedocumentGetListV1(
    eOrderBy,
    iRowMax,
    iRowOffset,
    acceptLanguage,
    sFilter
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **eOrderBy** | [**&#39;pkiEzdoctemplatedocumentID_ASC&#39; | &#39;pkiEzdoctemplatedocumentID_DESC&#39; | &#39;fkiLanguageID_ASC&#39; | &#39;fkiLanguageID_DESC&#39; | &#39;fkiEzdoctemplatetypeID_ASC&#39; | &#39;fkiEzdoctemplatetypeID_DESC&#39; | &#39;fkiEzdoctemplatefieldtypecategoryID_ASC&#39; | &#39;fkiEzdoctemplatefieldtypecategoryID_DESC&#39; | &#39;bEzdoctemplatedocumentIsactive_ASC&#39; | &#39;bEzdoctemplatedocumentIsactive_DESC&#39; | &#39;sEzdoctemplatedocumentNameX_ASC&#39; | &#39;sEzdoctemplatedocumentNameX_DESC&#39;**]**Array<&#39;pkiEzdoctemplatedocumentID_ASC&#39; &#124; &#39;pkiEzdoctemplatedocumentID_DESC&#39; &#124; &#39;fkiLanguageID_ASC&#39; &#124; &#39;fkiLanguageID_DESC&#39; &#124; &#39;fkiEzdoctemplatetypeID_ASC&#39; &#124; &#39;fkiEzdoctemplatetypeID_DESC&#39; &#124; &#39;fkiEzdoctemplatefieldtypecategoryID_ASC&#39; &#124; &#39;fkiEzdoctemplatefieldtypecategoryID_DESC&#39; &#124; &#39;bEzdoctemplatedocumentIsactive_ASC&#39; &#124; &#39;bEzdoctemplatedocumentIsactive_DESC&#39; &#124; &#39;sEzdoctemplatedocumentNameX_ASC&#39; &#124; &#39;sEzdoctemplatedocumentNameX_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**EzdoctemplatedocumentGetListV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezdoctemplatedocumentGetObjectV2**
> EzdoctemplatedocumentGetObjectV2Response ezdoctemplatedocumentGetObjectV2()



### Example

```typescript
import {
    ObjectEzdoctemplatedocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzdoctemplatedocumentApi(configuration);

let pkiEzdoctemplatedocumentID: number; //The unique ID of the Ezdoctemplatedocument (default to undefined)

const { status, data } = await apiInstance.ezdoctemplatedocumentGetObjectV2(
    pkiEzdoctemplatedocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzdoctemplatedocumentID** | [**number**] | The unique ID of the Ezdoctemplatedocument | defaults to undefined|


### Return type

**EzdoctemplatedocumentGetObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezdoctemplatedocumentPatchObjectV1**
> EzdoctemplatedocumentPatchObjectV1Response ezdoctemplatedocumentPatchObjectV1(ezdoctemplatedocumentPatchObjectV1Request)



### Example

```typescript
import {
    ObjectEzdoctemplatedocumentApi,
    Configuration,
    EzdoctemplatedocumentPatchObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzdoctemplatedocumentApi(configuration);

let pkiEzdoctemplatedocumentID: number; //The unique ID of the Ezdoctemplatedocument (default to undefined)
let ezdoctemplatedocumentPatchObjectV1Request: EzdoctemplatedocumentPatchObjectV1Request; //

const { status, data } = await apiInstance.ezdoctemplatedocumentPatchObjectV1(
    pkiEzdoctemplatedocumentID,
    ezdoctemplatedocumentPatchObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezdoctemplatedocumentPatchObjectV1Request** | **EzdoctemplatedocumentPatchObjectV1Request**|  | |
| **pkiEzdoctemplatedocumentID** | [**number**] | The unique ID of the Ezdoctemplatedocument | defaults to undefined|


### Return type

**EzdoctemplatedocumentPatchObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

