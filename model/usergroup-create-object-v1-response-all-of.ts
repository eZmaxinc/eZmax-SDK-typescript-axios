/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { UsergroupCreateObjectV1ResponseMPayload } from './usergroup-create-object-v1-response-mpayload';

/**
 * 
 * @export
 * @interface UsergroupCreateObjectV1ResponseAllOf
 */
export interface UsergroupCreateObjectV1ResponseAllOf {
    /**
     * 
     * @type {UsergroupCreateObjectV1ResponseMPayload}
     * @memberof UsergroupCreateObjectV1ResponseAllOf
     */
    'mPayload': UsergroupCreateObjectV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUsergroupCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectUsergroupCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A UsergroupCreateObjectV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupCreateObjectV1ResponseAllOf
 */
export class DataObjectUsergroupCreateObjectV1ResponseAllOf {
   mPayload:UsergroupCreateObjectV1ResponseMPayload = new DataObjectUsergroupCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A UsergroupCreateObjectV1ResponseAllOf Validation Object
 * @class ValidationObjectUsergroupCreateObjectV1ResponseAllOf
 */
export class ValidationObjectUsergroupCreateObjectV1ResponseAllOf {
   mPayload = new ValidationObjectUsergroupCreateObjectV1ResponseMPayload()
} 


