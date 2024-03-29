/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { ActivesessionGetCurrentV1ResponseMPayload } from './activesession-get-current-v1-response-mpayload';

/**
 * 
 * @export
 * @interface ActivesessionGetCurrentV1ResponseAllOf
 */
export interface ActivesessionGetCurrentV1ResponseAllOf {
    /**
     * 
     * @type {ActivesessionGetCurrentV1ResponseMPayload}
     * @memberof ActivesessionGetCurrentV1ResponseAllOf
     */
    'mPayload': ActivesessionGetCurrentV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectActivesessionGetCurrentV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectActivesessionGetCurrentV1ResponseMPayload } from './'

/**
 * @export 
 * A ActivesessionGetCurrentV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectActivesessionGetCurrentV1ResponseAllOf
 */
export class DataObjectActivesessionGetCurrentV1ResponseAllOf {
   mPayload:ActivesessionGetCurrentV1ResponseMPayload = new DataObjectActivesessionGetCurrentV1ResponseMPayload()
}

/**
 * @export 
 * A ActivesessionGetCurrentV1ResponseAllOf Validation Object
 * @class ValidationObjectActivesessionGetCurrentV1ResponseAllOf
 */
export class ValidationObjectActivesessionGetCurrentV1ResponseAllOf {
   mPayload = new ValidationObjectActivesessionGetCurrentV1ResponseMPayload()
} 


