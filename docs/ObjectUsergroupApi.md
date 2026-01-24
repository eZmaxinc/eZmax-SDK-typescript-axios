# ObjectUsergroupApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**usergroupCreateObjectV1**](#usergroupcreateobjectv1) | **POST** /1/object/usergroup | Create a new Usergroup|
|[**usergroupEditObjectV1**](#usergroupeditobjectv1) | **PUT** /1/object/usergroup/{pkiUsergroupID} | Edit an existing Usergroup|
|[**usergroupEditPermissionsV1**](#usergroupeditpermissionsv1) | **PUT** /1/object/usergroup/{pkiUsergroupID}/editPermissions | Edit multiple Permissions|
|[**usergroupEditUsergroupdelegationsV1**](#usergroupeditusergroupdelegationsv1) | **PUT** /1/object/usergroup/{pkiUsergroupID}/editUsergroupdelegations | Edit multiple Usergroupdelegations|
|[**usergroupEditUsergroupmembershipsV1**](#usergroupeditusergroupmembershipsv1) | **PUT** /1/object/usergroup/{pkiUsergroupID}/editUsergroupmemberships | Edit multiple Usergroupmemberships|
|[**usergroupGetAutocompleteV2**](#usergroupgetautocompletev2) | **GET** /2/object/usergroup/getAutocomplete/{sSelector} | Retrieve Usergroups and IDs|
|[**usergroupGetListV1**](#usergroupgetlistv1) | **GET** /1/object/usergroup/getList | Retrieve Usergroup list|
|[**usergroupGetObjectV2**](#usergroupgetobjectv2) | **GET** /2/object/usergroup/{pkiUsergroupID} | Retrieve an existing Usergroup|
|[**usergroupGetPermissionsV1**](#usergroupgetpermissionsv1) | **GET** /1/object/usergroup/{pkiUsergroupID}/getPermissions | Retrieve an existing Usergroup\&#39;s Permissions|
|[**usergroupGetUsergroupdelegationsV1**](#usergroupgetusergroupdelegationsv1) | **GET** /1/object/usergroup/{pkiUsergroupID}/getUsergroupdelegations | Retrieve an existing Usergroup\&#39;s Usergroupdelegations|
|[**usergroupGetUsergroupmembershipsV1**](#usergroupgetusergroupmembershipsv1) | **GET** /1/object/usergroup/{pkiUsergroupID}/getUsergroupmemberships | Retrieve an existing Usergroup\&#39;s Usergroupmemberships|

# **usergroupCreateObjectV1**
> UsergroupCreateObjectV1Response usergroupCreateObjectV1(usergroupCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectUsergroupApi,
    Configuration,
    UsergroupCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupApi(configuration);

let usergroupCreateObjectV1Request: UsergroupCreateObjectV1Request; //

const { status, data } = await apiInstance.usergroupCreateObjectV1(
    usergroupCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **usergroupCreateObjectV1Request** | **UsergroupCreateObjectV1Request**|  | |


### Return type

**UsergroupCreateObjectV1Response**

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

# **usergroupEditObjectV1**
> UsergroupEditObjectV1Response usergroupEditObjectV1(usergroupEditObjectV1Request)



### Example

```typescript
import {
    ObjectUsergroupApi,
    Configuration,
    UsergroupEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupApi(configuration);

let pkiUsergroupID: number; // (default to undefined)
let usergroupEditObjectV1Request: UsergroupEditObjectV1Request; //

const { status, data } = await apiInstance.usergroupEditObjectV1(
    pkiUsergroupID,
    usergroupEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **usergroupEditObjectV1Request** | **UsergroupEditObjectV1Request**|  | |
| **pkiUsergroupID** | [**number**] |  | defaults to undefined|


### Return type

**UsergroupEditObjectV1Response**

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

# **usergroupEditPermissionsV1**
> UsergroupEditPermissionsV1Response usergroupEditPermissionsV1(usergroupEditPermissionsV1Request)

Using this endpoint, you can edit multiple Permissions at the same time.

### Example

```typescript
import {
    ObjectUsergroupApi,
    Configuration,
    UsergroupEditPermissionsV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupApi(configuration);

let pkiUsergroupID: number; // (default to undefined)
let usergroupEditPermissionsV1Request: UsergroupEditPermissionsV1Request; //

const { status, data } = await apiInstance.usergroupEditPermissionsV1(
    pkiUsergroupID,
    usergroupEditPermissionsV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **usergroupEditPermissionsV1Request** | **UsergroupEditPermissionsV1Request**|  | |
| **pkiUsergroupID** | [**number**] |  | defaults to undefined|


### Return type

**UsergroupEditPermissionsV1Response**

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

# **usergroupEditUsergroupdelegationsV1**
> UsergroupEditUsergroupdelegationsV1Response usergroupEditUsergroupdelegationsV1(usergroupEditUsergroupdelegationsV1Request)

Edit multiple Usergroupdelegations

### Example

```typescript
import {
    ObjectUsergroupApi,
    Configuration,
    UsergroupEditUsergroupdelegationsV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupApi(configuration);

let pkiUsergroupID: number; // (default to undefined)
let usergroupEditUsergroupdelegationsV1Request: UsergroupEditUsergroupdelegationsV1Request; //

const { status, data } = await apiInstance.usergroupEditUsergroupdelegationsV1(
    pkiUsergroupID,
    usergroupEditUsergroupdelegationsV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **usergroupEditUsergroupdelegationsV1Request** | **UsergroupEditUsergroupdelegationsV1Request**|  | |
| **pkiUsergroupID** | [**number**] |  | defaults to undefined|


### Return type

**UsergroupEditUsergroupdelegationsV1Response**

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

# **usergroupEditUsergroupmembershipsV1**
> UsergroupEditUsergroupmembershipsV1Response usergroupEditUsergroupmembershipsV1(usergroupEditUsergroupmembershipsV1Request)

Using this endpoint, you can edit multiple Usergroupmemberships at the same time.

### Example

```typescript
import {
    ObjectUsergroupApi,
    Configuration,
    UsergroupEditUsergroupmembershipsV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupApi(configuration);

let pkiUsergroupID: number; // (default to undefined)
let usergroupEditUsergroupmembershipsV1Request: UsergroupEditUsergroupmembershipsV1Request; //

const { status, data } = await apiInstance.usergroupEditUsergroupmembershipsV1(
    pkiUsergroupID,
    usergroupEditUsergroupmembershipsV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **usergroupEditUsergroupmembershipsV1Request** | **UsergroupEditUsergroupmembershipsV1Request**|  | |
| **pkiUsergroupID** | [**number**] |  | defaults to undefined|


### Return type

**UsergroupEditUsergroupmembershipsV1Response**

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

# **usergroupGetAutocompleteV2**
> UsergroupGetAutocompleteV2Response usergroupGetAutocompleteV2()

Get the list of Usergroup to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectUsergroupApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupApi(configuration);

let sSelector: 'All' | 'AllButEveryone'; //The type of Usergroups to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.usergroupGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39; | &#39;AllButEveryone&#39;**]**Array<&#39;All&#39; &#124; &#39;AllButEveryone&#39;>** | The type of Usergroups to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**UsergroupGetAutocompleteV2Response**

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

# **usergroupGetListV1**
> UsergroupGetListV1Response usergroupGetListV1()



### Example

```typescript
import {
    ObjectUsergroupApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupApi(configuration);

let eOrderBy: 'pkiUsergroupID_ASC' | 'pkiUsergroupID_DESC' | 'sUsergroupNameX_ASC' | 'sUsergroupNameX_DESC' | 'iCountUser_ASC' | 'iCountUser_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.usergroupGetListV1(
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
| **eOrderBy** | [**&#39;pkiUsergroupID_ASC&#39; | &#39;pkiUsergroupID_DESC&#39; | &#39;sUsergroupNameX_ASC&#39; | &#39;sUsergroupNameX_DESC&#39; | &#39;iCountUser_ASC&#39; | &#39;iCountUser_DESC&#39;**]**Array<&#39;pkiUsergroupID_ASC&#39; &#124; &#39;pkiUsergroupID_DESC&#39; &#124; &#39;sUsergroupNameX_ASC&#39; &#124; &#39;sUsergroupNameX_DESC&#39; &#124; &#39;iCountUser_ASC&#39; &#124; &#39;iCountUser_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**UsergroupGetListV1Response**

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

# **usergroupGetObjectV2**
> UsergroupGetObjectV2Response usergroupGetObjectV2()



### Example

```typescript
import {
    ObjectUsergroupApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupApi(configuration);

let pkiUsergroupID: number; // (default to undefined)

const { status, data } = await apiInstance.usergroupGetObjectV2(
    pkiUsergroupID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiUsergroupID** | [**number**] |  | defaults to undefined|


### Return type

**UsergroupGetObjectV2Response**

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

# **usergroupGetPermissionsV1**
> UsergroupGetPermissionsV1Response usergroupGetPermissionsV1()


### Example

```typescript
import {
    ObjectUsergroupApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupApi(configuration);

let pkiUsergroupID: number; // (default to undefined)

const { status, data } = await apiInstance.usergroupGetPermissionsV1(
    pkiUsergroupID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiUsergroupID** | [**number**] |  | defaults to undefined|


### Return type

**UsergroupGetPermissionsV1Response**

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

# **usergroupGetUsergroupdelegationsV1**
> UsergroupGetUsergroupdelegationsV1Response usergroupGetUsergroupdelegationsV1()


### Example

```typescript
import {
    ObjectUsergroupApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupApi(configuration);

let pkiUsergroupID: number; // (default to undefined)

const { status, data } = await apiInstance.usergroupGetUsergroupdelegationsV1(
    pkiUsergroupID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiUsergroupID** | [**number**] |  | defaults to undefined|


### Return type

**UsergroupGetUsergroupdelegationsV1Response**

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

# **usergroupGetUsergroupmembershipsV1**
> UsergroupGetUsergroupmembershipsV1Response usergroupGetUsergroupmembershipsV1()


### Example

```typescript
import {
    ObjectUsergroupApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupApi(configuration);

let pkiUsergroupID: number; // (default to undefined)

const { status, data } = await apiInstance.usergroupGetUsergroupmembershipsV1(
    pkiUsergroupID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiUsergroupID** | [**number**] |  | defaults to undefined|


### Return type

**UsergroupGetUsergroupmembershipsV1Response**

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

