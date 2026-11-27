# ObjectEzsigntemplateApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsigntemplateCopyV1**](#ezsigntemplatecopyv1) | **POST** /1/object/ezsigntemplate/{pkiEzsigntemplateID}/copy | Copy the Ezsigntemplate|
|[**ezsigntemplateCreateObjectV3**](#ezsigntemplatecreateobjectv3) | **POST** /3/object/ezsigntemplate | Create a new Ezsigntemplate|
|[**ezsigntemplateDeleteObjectV1**](#ezsigntemplatedeleteobjectv1) | **DELETE** /1/object/ezsigntemplate/{pkiEzsigntemplateID} | Delete an existing Ezsigntemplate|
|[**ezsigntemplateEditObjectV3**](#ezsigntemplateeditobjectv3) | **PUT** /3/object/ezsigntemplate/{pkiEzsigntemplateID} | Edit an existing Ezsigntemplate|
|[**ezsigntemplateGetAutocompleteV2**](#ezsigntemplategetautocompletev2) | **GET** /2/object/ezsigntemplate/getAutocomplete/{sSelector} | Retrieve Ezsigntemplates and IDs|
|[**ezsigntemplateGetListV1**](#ezsigntemplategetlistv1) | **GET** /1/object/ezsigntemplate/getList | Retrieve Ezsigntemplate list|
|[**ezsigntemplateGetObjectV3**](#ezsigntemplategetobjectv3) | **GET** /3/object/ezsigntemplate/{pkiEzsigntemplateID} | Retrieve an existing Ezsigntemplate|
|[**ezsigntemplateGetObjectV4**](#ezsigntemplategetobjectv4) | **GET** /4/object/ezsigntemplate/{pkiEzsigntemplateID} | Retrieve an existing Ezsigntemplate|

# **ezsigntemplateCopyV1**
> EzsigntemplateCopyV1Response ezsigntemplateCopyV1(ezsigntemplateCopyV1Request)



### Example

```typescript
import {
    ObjectEzsigntemplateApi,
    Configuration,
    EzsigntemplateCopyV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplateApi(configuration);

let pkiEzsigntemplateID: number; // (default to undefined)
let ezsigntemplateCopyV1Request: EzsigntemplateCopyV1Request; //

const { status, data } = await apiInstance.ezsigntemplateCopyV1(
    pkiEzsigntemplateID,
    ezsigntemplateCopyV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplateCopyV1Request** | **EzsigntemplateCopyV1Request**|  | |
| **pkiEzsigntemplateID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplateCopyV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigntemplateCreateObjectV3**
> EzsigntemplateCreateObjectV3Response ezsigntemplateCreateObjectV3(ezsigntemplateCreateObjectV3Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsigntemplateApi,
    Configuration,
    EzsigntemplateCreateObjectV3Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplateApi(configuration);

let ezsigntemplateCreateObjectV3Request: EzsigntemplateCreateObjectV3Request; //

const { status, data } = await apiInstance.ezsigntemplateCreateObjectV3(
    ezsigntemplateCreateObjectV3Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplateCreateObjectV3Request** | **EzsigntemplateCreateObjectV3Request**|  | |


### Return type

**EzsigntemplateCreateObjectV3Response**

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

# **ezsigntemplateDeleteObjectV1**
> EzsigntemplateDeleteObjectV1Response ezsigntemplateDeleteObjectV1()



### Example

```typescript
import {
    ObjectEzsigntemplateApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplateApi(configuration);

let pkiEzsigntemplateID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplateDeleteObjectV1(
    pkiEzsigntemplateID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplateID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplateDeleteObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigntemplateEditObjectV3**
> EzsigntemplateEditObjectV3Response ezsigntemplateEditObjectV3(ezsigntemplateEditObjectV3Request)



### Example

```typescript
import {
    ObjectEzsigntemplateApi,
    Configuration,
    EzsigntemplateEditObjectV3Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplateApi(configuration);

let pkiEzsigntemplateID: number; // (default to undefined)
let ezsigntemplateEditObjectV3Request: EzsigntemplateEditObjectV3Request; //

const { status, data } = await apiInstance.ezsigntemplateEditObjectV3(
    pkiEzsigntemplateID,
    ezsigntemplateEditObjectV3Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplateEditObjectV3Request** | **EzsigntemplateEditObjectV3Request**|  | |
| **pkiEzsigntemplateID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplateEditObjectV3Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigntemplateGetAutocompleteV2**
> EzsigntemplateGetAutocompleteV2Response ezsigntemplateGetAutocompleteV2()

Get the list of Ezsigntemplate to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectEzsigntemplateApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplateApi(configuration);

let sSelector: 'All' | 'Ezsigntemplatepublic'; //The type of Ezsigntemplates to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let fkiEzsignfoldertypeID: number; //The fkiEzsignfoldertypeID to use with the selector Ezsigntemplatepublic (optional) (default to undefined)

const { status, data } = await apiInstance.ezsigntemplateGetAutocompleteV2(
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
| **sSelector** | [**&#39;All&#39; | &#39;Ezsigntemplatepublic&#39;**]**Array<&#39;All&#39; &#124; &#39;Ezsigntemplatepublic&#39;>** | The type of Ezsigntemplates to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **fkiEzsignfoldertypeID** | [**number**] | The fkiEzsignfoldertypeID to use with the selector Ezsigntemplatepublic | (optional) defaults to undefined|


### Return type

**EzsigntemplateGetAutocompleteV2Response**

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

# **ezsigntemplateGetListV1**
> EzsigntemplateGetListV1Response ezsigntemplateGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eEzsigntemplateType | Company<br>Team<br>User<br>Usergroup | 

### Example

```typescript
import {
    ObjectEzsigntemplateApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplateApi(configuration);

let eOrderBy: 'pkiEzsigntemplateID_ASC' | 'pkiEzsigntemplateID_DESC' | 'fkiEzsignfoldertypeID_ASC' | 'fkiEzsignfoldertypeID_DESC' | 'fkiUserIDOwner_ASC' | 'fkiUserIDOwner_DESC' | 'fkiLanguageID_ASC' | 'fkiLanguageID_DESC' | 'eEzsigntemplateType_ASC' | 'eEzsigntemplateType_DESC' | 'sEzsigntemplateDescription_ASC' | 'sEzsigntemplateDescription_DESC' | 'iEzsigntemplatedocumentPagetotal_ASC' | 'iEzsigntemplatedocumentPagetotal_DESC' | 'iEzsigntemplateSignaturetotal_ASC' | 'iEzsigntemplateSignaturetotal_DESC' | 'sEzsignfoldertypeNameX_ASC' | 'sEzsignfoldertypeNameX_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.ezsigntemplateGetListV1(
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
| **eOrderBy** | [**&#39;pkiEzsigntemplateID_ASC&#39; | &#39;pkiEzsigntemplateID_DESC&#39; | &#39;fkiEzsignfoldertypeID_ASC&#39; | &#39;fkiEzsignfoldertypeID_DESC&#39; | &#39;fkiUserIDOwner_ASC&#39; | &#39;fkiUserIDOwner_DESC&#39; | &#39;fkiLanguageID_ASC&#39; | &#39;fkiLanguageID_DESC&#39; | &#39;eEzsigntemplateType_ASC&#39; | &#39;eEzsigntemplateType_DESC&#39; | &#39;sEzsigntemplateDescription_ASC&#39; | &#39;sEzsigntemplateDescription_DESC&#39; | &#39;iEzsigntemplatedocumentPagetotal_ASC&#39; | &#39;iEzsigntemplatedocumentPagetotal_DESC&#39; | &#39;iEzsigntemplateSignaturetotal_ASC&#39; | &#39;iEzsigntemplateSignaturetotal_DESC&#39; | &#39;sEzsignfoldertypeNameX_ASC&#39; | &#39;sEzsignfoldertypeNameX_DESC&#39;**]**Array<&#39;pkiEzsigntemplateID_ASC&#39; &#124; &#39;pkiEzsigntemplateID_DESC&#39; &#124; &#39;fkiEzsignfoldertypeID_ASC&#39; &#124; &#39;fkiEzsignfoldertypeID_DESC&#39; &#124; &#39;fkiUserIDOwner_ASC&#39; &#124; &#39;fkiUserIDOwner_DESC&#39; &#124; &#39;fkiLanguageID_ASC&#39; &#124; &#39;fkiLanguageID_DESC&#39; &#124; &#39;eEzsigntemplateType_ASC&#39; &#124; &#39;eEzsigntemplateType_DESC&#39; &#124; &#39;sEzsigntemplateDescription_ASC&#39; &#124; &#39;sEzsigntemplateDescription_DESC&#39; &#124; &#39;iEzsigntemplatedocumentPagetotal_ASC&#39; &#124; &#39;iEzsigntemplatedocumentPagetotal_DESC&#39; &#124; &#39;iEzsigntemplateSignaturetotal_ASC&#39; &#124; &#39;iEzsigntemplateSignaturetotal_DESC&#39; &#124; &#39;sEzsignfoldertypeNameX_ASC&#39; &#124; &#39;sEzsignfoldertypeNameX_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**EzsigntemplateGetListV1Response**

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

# **ezsigntemplateGetObjectV3**
> EzsigntemplateGetObjectV3Response ezsigntemplateGetObjectV3()



### Example

```typescript
import {
    ObjectEzsigntemplateApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplateApi(configuration);

let pkiEzsigntemplateID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplateGetObjectV3(
    pkiEzsigntemplateID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplateID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplateGetObjectV3Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigntemplateGetObjectV4**
> EzsigntemplateGetObjectV4Response ezsigntemplateGetObjectV4()



### Example

```typescript
import {
    ObjectEzsigntemplateApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplateApi(configuration);

let pkiEzsigntemplateID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplateGetObjectV4(
    pkiEzsigntemplateID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplateID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplateGetObjectV4Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

