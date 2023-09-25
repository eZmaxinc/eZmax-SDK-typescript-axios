/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { ScimAuthenticationScheme } from './scim-authentication-scheme';
// May contain unused imports in some cases
// @ts-ignore
import { ScimServiceProviderConfigBulk } from './scim-service-provider-config-bulk';
// May contain unused imports in some cases
// @ts-ignore
import { ScimServiceProviderConfigChangePassword } from './scim-service-provider-config-change-password';
// May contain unused imports in some cases
// @ts-ignore
import { ScimServiceProviderConfigEtag } from './scim-service-provider-config-etag';
// May contain unused imports in some cases
// @ts-ignore
import { ScimServiceProviderConfigFilter } from './scim-service-provider-config-filter';
// May contain unused imports in some cases
// @ts-ignore
import { ScimServiceProviderConfigPatch } from './scim-service-provider-config-patch';
// May contain unused imports in some cases
// @ts-ignore
import { ScimServiceProviderConfigSort } from './scim-service-provider-config-sort';

/**
 * 
 * @export
 * @interface ScimServiceProviderConfig
 */
export interface ScimServiceProviderConfig {
    /**
     * A multi-valued complex type that specifies supported authentication scheme properties.
     * @type {Array<ScimAuthenticationScheme>}
     * @memberof ScimServiceProviderConfig
     */
    'authenticationSchemes': Array<ScimAuthenticationScheme>;
    /**
     * 
     * @type {ScimServiceProviderConfigBulk}
     * @memberof ScimServiceProviderConfig
     */
    'bulk': ScimServiceProviderConfigBulk;
    /**
     * 
     * @type {ScimServiceProviderConfigChangePassword}
     * @memberof ScimServiceProviderConfig
     */
    'changePassword': ScimServiceProviderConfigChangePassword;
    /**
     * An HTTP-addressable URL pointing to the service provider\'s human-consumable help documentation
     * @type {string}
     * @memberof ScimServiceProviderConfig
     */
    'documentationUri': string;
    /**
     * 
     * @type {ScimServiceProviderConfigEtag}
     * @memberof ScimServiceProviderConfig
     */
    'etag': ScimServiceProviderConfigEtag;
    /**
     * 
     * @type {ScimServiceProviderConfigFilter}
     * @memberof ScimServiceProviderConfig
     */
    'filter': ScimServiceProviderConfigFilter;
    /**
     * 
     * @type {ScimServiceProviderConfigPatch}
     * @memberof ScimServiceProviderConfig
     */
    'patch': ScimServiceProviderConfigPatch;
    /**
     * 
     * @type {ScimServiceProviderConfigSort}
     * @memberof ScimServiceProviderConfig
     */
    'sort': ScimServiceProviderConfigSort;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectScimServiceProviderConfigBulk } from './'
// @ts-ignore
import { DataObjectScimServiceProviderConfigChangePassword } from './'
// @ts-ignore
import { DataObjectScimServiceProviderConfigEtag } from './'
// @ts-ignore
import { DataObjectScimServiceProviderConfigFilter } from './'
// @ts-ignore
import { DataObjectScimServiceProviderConfigPatch } from './'
// @ts-ignore
import { DataObjectScimServiceProviderConfigSort } from './'
// @ts-ignore
import { ValidationObjectScimServiceProviderConfigBulk } from './'
// @ts-ignore
import { ValidationObjectScimServiceProviderConfigChangePassword } from './'
// @ts-ignore
import { ValidationObjectScimServiceProviderConfigEtag } from './'
// @ts-ignore
import { ValidationObjectScimServiceProviderConfigFilter } from './'
// @ts-ignore
import { ValidationObjectScimServiceProviderConfigPatch } from './'
// @ts-ignore
import { ValidationObjectScimServiceProviderConfigSort } from './'

/**
 * @export 
 * A ScimServiceProviderConfig Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectScimServiceProviderConfig
 */
export class DataObjectScimServiceProviderConfig {
   authenticationSchemes:Array<ScimAuthenticationScheme> = []
   bulk:ScimServiceProviderConfigBulk = new DataObjectScimServiceProviderConfigBulk()
   changePassword:ScimServiceProviderConfigChangePassword = new DataObjectScimServiceProviderConfigChangePassword()
   documentationUri:string = ''
   etag:ScimServiceProviderConfigEtag = new DataObjectScimServiceProviderConfigEtag()
   filter:ScimServiceProviderConfigFilter = new DataObjectScimServiceProviderConfigFilter()
   patch:ScimServiceProviderConfigPatch = new DataObjectScimServiceProviderConfigPatch()
   sort:ScimServiceProviderConfigSort = new DataObjectScimServiceProviderConfigSort()
}

/**
 * @export 
 * A ScimServiceProviderConfig Validation Object
 * @class ValidationObjectScimServiceProviderConfig
 */
export class ValidationObjectScimServiceProviderConfig {
   authenticationSchemes = {
      type: 'array',
      required: true
   }
   bulk = new ValidationObjectScimServiceProviderConfigBulk()
   changePassword = new ValidationObjectScimServiceProviderConfigChangePassword()
   documentationUri = {
      type: 'string',
      required: true
   }
   etag = new ValidationObjectScimServiceProviderConfigEtag()
   filter = new ValidationObjectScimServiceProviderConfigFilter()
   patch = new ValidationObjectScimServiceProviderConfigPatch()
   sort = new ValidationObjectScimServiceProviderConfigSort()
} 


