# ObjectEzsigntemplatepackageApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsigntemplatepackageCreateObjectV1**](#ezsigntemplatepackagecreateobjectv1) | **POST** /1/object/ezsigntemplatepackage | Create a new Ezsigntemplatepackage|
|[**ezsigntemplatepackageDeleteObjectV1**](#ezsigntemplatepackagedeleteobjectv1) | **DELETE** /1/object/ezsigntemplatepackage/{pkiEzsigntemplatepackageID} | Delete an existing Ezsigntemplatepackage|
|[**ezsigntemplatepackageEditEzsigntemplatepackagesignersV1**](#ezsigntemplatepackageeditezsigntemplatepackagesignersv1) | **PUT** /1/object/ezsigntemplatepackage/{pkiEzsigntemplatepackageID}/editEzsigntemplatepackagesigners | Edit multiple Ezsigntemplatepackagesigners|
|[**ezsigntemplatepackageEditEzsigntemplatepackagesignersV2**](#ezsigntemplatepackageeditezsigntemplatepackagesignersv2) | **PUT** /2/object/ezsigntemplatepackage/{pkiEzsigntemplatepackageID}/editEzsigntemplatepackagesigners | Edit multiple Ezsigntemplatepackagesigners|
|[**ezsigntemplatepackageEditObjectV1**](#ezsigntemplatepackageeditobjectv1) | **PUT** /1/object/ezsigntemplatepackage/{pkiEzsigntemplatepackageID} | Edit an existing Ezsigntemplatepackage|
|[**ezsigntemplatepackageGetAutocompleteV2**](#ezsigntemplatepackagegetautocompletev2) | **GET** /2/object/ezsigntemplatepackage/getAutocomplete/{sSelector} | Retrieve Ezsigntemplatepackages and IDs|
|[**ezsigntemplatepackageGetListV1**](#ezsigntemplatepackagegetlistv1) | **GET** /1/object/ezsigntemplatepackage/getList | Retrieve Ezsigntemplatepackage list|
|[**ezsigntemplatepackageGetObjectV2**](#ezsigntemplatepackagegetobjectv2) | **GET** /2/object/ezsigntemplatepackage/{pkiEzsigntemplatepackageID} | Retrieve an existing Ezsigntemplatepackage|
|[**ezsigntemplatepackageGetObjectV3**](#ezsigntemplatepackagegetobjectv3) | **GET** /3/object/ezsigntemplatepackage/{pkiEzsigntemplatepackageID} | Retrieve an existing Ezsigntemplatepackage|

# **ezsigntemplatepackageCreateObjectV1**
> EzsigntemplatepackageCreateObjectV1Response ezsigntemplatepackageCreateObjectV1(ezsigntemplatepackageCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsigntemplatepackageApi,
    Configuration,
    EzsigntemplatepackageCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepackageApi(configuration);

let ezsigntemplatepackageCreateObjectV1Request: EzsigntemplatepackageCreateObjectV1Request; //

const { status, data } = await apiInstance.ezsigntemplatepackageCreateObjectV1(
    ezsigntemplatepackageCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatepackageCreateObjectV1Request** | **EzsigntemplatepackageCreateObjectV1Request**|  | |


### Return type

**EzsigntemplatepackageCreateObjectV1Response**

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

# **ezsigntemplatepackageDeleteObjectV1**
> EzsigntemplatepackageDeleteObjectV1Response ezsigntemplatepackageDeleteObjectV1()



### Example

```typescript
import {
    ObjectEzsigntemplatepackageApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepackageApi(configuration);

let pkiEzsigntemplatepackageID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatepackageDeleteObjectV1(
    pkiEzsigntemplatepackageID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatepackageID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatepackageDeleteObjectV1Response**

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

# **ezsigntemplatepackageEditEzsigntemplatepackagesignersV1**
> EzsigntemplatepackageEditEzsigntemplatepackagesignersV1Response ezsigntemplatepackageEditEzsigntemplatepackagesignersV1(ezsigntemplatepackageEditEzsigntemplatepackagesignersV1Request)

Using this endpoint, you can edit multiple Ezsigntemplatepackagesigners at the same time.

### Example

```typescript
import {
    ObjectEzsigntemplatepackageApi,
    Configuration,
    EzsigntemplatepackageEditEzsigntemplatepackagesignersV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepackageApi(configuration);

let pkiEzsigntemplatepackageID: number; // (default to undefined)
let ezsigntemplatepackageEditEzsigntemplatepackagesignersV1Request: EzsigntemplatepackageEditEzsigntemplatepackagesignersV1Request; //

const { status, data } = await apiInstance.ezsigntemplatepackageEditEzsigntemplatepackagesignersV1(
    pkiEzsigntemplatepackageID,
    ezsigntemplatepackageEditEzsigntemplatepackagesignersV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatepackageEditEzsigntemplatepackagesignersV1Request** | **EzsigntemplatepackageEditEzsigntemplatepackagesignersV1Request**|  | |
| **pkiEzsigntemplatepackageID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatepackageEditEzsigntemplatepackagesignersV1Response**

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

# **ezsigntemplatepackageEditEzsigntemplatepackagesignersV2**
> EzsigntemplatepackageEditEzsigntemplatepackagesignersV2Response ezsigntemplatepackageEditEzsigntemplatepackagesignersV2(ezsigntemplatepackageEditEzsigntemplatepackagesignersV2Request)

Using this endpoint, you can edit multiple Ezsigntemplatepackagesigners at the same time.

### Example

```typescript
import {
    ObjectEzsigntemplatepackageApi,
    Configuration,
    EzsigntemplatepackageEditEzsigntemplatepackagesignersV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepackageApi(configuration);

let pkiEzsigntemplatepackageID: number; // (default to undefined)
let ezsigntemplatepackageEditEzsigntemplatepackagesignersV2Request: EzsigntemplatepackageEditEzsigntemplatepackagesignersV2Request; //

const { status, data } = await apiInstance.ezsigntemplatepackageEditEzsigntemplatepackagesignersV2(
    pkiEzsigntemplatepackageID,
    ezsigntemplatepackageEditEzsigntemplatepackagesignersV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatepackageEditEzsigntemplatepackagesignersV2Request** | **EzsigntemplatepackageEditEzsigntemplatepackagesignersV2Request**|  | |
| **pkiEzsigntemplatepackageID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatepackageEditEzsigntemplatepackagesignersV2Response**

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

# **ezsigntemplatepackageEditObjectV1**
> EzsigntemplatepackageEditObjectV1Response ezsigntemplatepackageEditObjectV1(ezsigntemplatepackageEditObjectV1Request)



### Example

```typescript
import {
    ObjectEzsigntemplatepackageApi,
    Configuration,
    EzsigntemplatepackageEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepackageApi(configuration);

let pkiEzsigntemplatepackageID: number; // (default to undefined)
let ezsigntemplatepackageEditObjectV1Request: EzsigntemplatepackageEditObjectV1Request; //

const { status, data } = await apiInstance.ezsigntemplatepackageEditObjectV1(
    pkiEzsigntemplatepackageID,
    ezsigntemplatepackageEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatepackageEditObjectV1Request** | **EzsigntemplatepackageEditObjectV1Request**|  | |
| **pkiEzsigntemplatepackageID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatepackageEditObjectV1Response**

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

# **ezsigntemplatepackageGetAutocompleteV2**
> EzsigntemplatepackageGetAutocompleteV2Response ezsigntemplatepackageGetAutocompleteV2()

Get the list of Ezsigntemplatepackage to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectEzsigntemplatepackageApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepackageApi(configuration);

let sSelector: 'All' | 'AllMultipleCopiesDisabled' | 'Ezsigntemplatepublic'; //The type of Ezsigntemplatepackages to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let fkiEzsignfoldertypeID: number; //The fkiEzsignfoldertypeID to use with the selector Ezsigntemplatepublic (optional) (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatepackageGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage,
    fkiEzsignfoldertypeID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39; | &#39;AllMultipleCopiesDisabled&#39; | &#39;Ezsigntemplatepublic&#39;**]**Array<&#39;All&#39; &#124; &#39;AllMultipleCopiesDisabled&#39; &#124; &#39;Ezsigntemplatepublic&#39;>** | The type of Ezsigntemplatepackages to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **fkiEzsignfoldertypeID** | [**number**] | The fkiEzsignfoldertypeID to use with the selector Ezsigntemplatepublic | (optional) defaults to undefined|


### Return type

**EzsigntemplatepackageGetAutocompleteV2Response**

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

# **ezsigntemplatepackageGetListV1**
> EzsigntemplatepackageGetListV1Response ezsigntemplatepackageGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eEzsigntemplatepackageType | Company<br>Team<br>User<br>Usergroup |

### Example

```typescript
import {
    ObjectEzsigntemplatepackageApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepackageApi(configuration);

let eOrderBy: 'pkiEzsigntemplatepackageID_ASC' | 'pkiEzsigntemplatepackageID_DESC' | 'fkiTeamID_ASC' | 'fkiTeamID_DESC' | 'fkiEzsignfoldertypeID_ASC' | 'fkiEzsignfoldertypeID_DESC' | 'fkiLanguageID_ASC' | 'fkiLanguageID_DESC' | 'eEzsigntemplatepackageType_ASC' | 'eEzsigntemplatepackageType_DESC' | 'sEzsigntemplatepackageDescription_ASC' | 'sEzsigntemplatepackageDescription_DESC' | 'bEzsigntemplatepackageNeedvalidation_ASC' | 'bEzsigntemplatepackageNeedvalidation_DESC' | 'iEzsigntemplatepackagemembership_ASC' | 'iEzsigntemplatepackagemembership_DESC' | 'bEzsigntemplatepackageIsactive_ASC' | 'bEzsigntemplatepackageIsactive_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatepackageGetListV1(
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
| **eOrderBy** | [**&#39;pkiEzsigntemplatepackageID_ASC&#39; | &#39;pkiEzsigntemplatepackageID_DESC&#39; | &#39;fkiTeamID_ASC&#39; | &#39;fkiTeamID_DESC&#39; | &#39;fkiEzsignfoldertypeID_ASC&#39; | &#39;fkiEzsignfoldertypeID_DESC&#39; | &#39;fkiLanguageID_ASC&#39; | &#39;fkiLanguageID_DESC&#39; | &#39;eEzsigntemplatepackageType_ASC&#39; | &#39;eEzsigntemplatepackageType_DESC&#39; | &#39;sEzsigntemplatepackageDescription_ASC&#39; | &#39;sEzsigntemplatepackageDescription_DESC&#39; | &#39;bEzsigntemplatepackageNeedvalidation_ASC&#39; | &#39;bEzsigntemplatepackageNeedvalidation_DESC&#39; | &#39;iEzsigntemplatepackagemembership_ASC&#39; | &#39;iEzsigntemplatepackagemembership_DESC&#39; | &#39;bEzsigntemplatepackageIsactive_ASC&#39; | &#39;bEzsigntemplatepackageIsactive_DESC&#39;**]**Array<&#39;pkiEzsigntemplatepackageID_ASC&#39; &#124; &#39;pkiEzsigntemplatepackageID_DESC&#39; &#124; &#39;fkiTeamID_ASC&#39; &#124; &#39;fkiTeamID_DESC&#39; &#124; &#39;fkiEzsignfoldertypeID_ASC&#39; &#124; &#39;fkiEzsignfoldertypeID_DESC&#39; &#124; &#39;fkiLanguageID_ASC&#39; &#124; &#39;fkiLanguageID_DESC&#39; &#124; &#39;eEzsigntemplatepackageType_ASC&#39; &#124; &#39;eEzsigntemplatepackageType_DESC&#39; &#124; &#39;sEzsigntemplatepackageDescription_ASC&#39; &#124; &#39;sEzsigntemplatepackageDescription_DESC&#39; &#124; &#39;bEzsigntemplatepackageNeedvalidation_ASC&#39; &#124; &#39;bEzsigntemplatepackageNeedvalidation_DESC&#39; &#124; &#39;iEzsigntemplatepackagemembership_ASC&#39; &#124; &#39;iEzsigntemplatepackagemembership_DESC&#39; &#124; &#39;bEzsigntemplatepackageIsactive_ASC&#39; &#124; &#39;bEzsigntemplatepackageIsactive_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**EzsigntemplatepackageGetListV1Response**

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

# **ezsigntemplatepackageGetObjectV2**
> EzsigntemplatepackageGetObjectV2Response ezsigntemplatepackageGetObjectV2()



### Example

```typescript
import {
    ObjectEzsigntemplatepackageApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepackageApi(configuration);

let pkiEzsigntemplatepackageID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatepackageGetObjectV2(
    pkiEzsigntemplatepackageID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatepackageID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatepackageGetObjectV2Response**

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

# **ezsigntemplatepackageGetObjectV3**
> EzsigntemplatepackageGetObjectV3Response ezsigntemplatepackageGetObjectV3()



### Example

```typescript
import {
    ObjectEzsigntemplatepackageApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepackageApi(configuration);

let pkiEzsigntemplatepackageID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatepackageGetObjectV3(
    pkiEzsigntemplatepackageID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatepackageID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatepackageGetObjectV3Response**

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

