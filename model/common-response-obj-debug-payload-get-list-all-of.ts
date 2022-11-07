/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseFilter } from './common-response-filter';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface CommonResponseObjDebugPayloadGetListAllOf
 */
export interface CommonResponseObjDebugPayloadGetListAllOf {
    /**
     * 
     * @type {CommonResponseFilter}
     * @memberof CommonResponseObjDebugPayloadGetListAllOf
     */
    'a_Filter': CommonResponseFilter;
    /**
     * List of available values for *eOrderBy*
     * @type {{ [key: string]: string; }}
     * @memberof CommonResponseObjDebugPayloadGetListAllOf
     */
    'a_OrderBy': { [key: string]: string; };
}
/**
 * A CommonResponseObjDebugPayloadGetListAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCommonResponseObjDebugPayloadGetListAllOf
 */
export class DefaultObjectCommonResponseObjDebugPayloadGetListAllOf extends DefaultObject {
   a_Filter:Partial<CommonResponseFilter> = {}
   a_OrderBy:{ [key: string]: string; } = {}
}


