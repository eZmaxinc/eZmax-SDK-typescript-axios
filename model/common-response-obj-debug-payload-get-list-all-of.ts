/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.5
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { CommonResponseFilter } from './common-response-filter';

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

