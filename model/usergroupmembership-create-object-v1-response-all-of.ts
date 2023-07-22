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
import { UsergroupmembershipCreateObjectV1ResponseMPayload } from './usergroupmembership-create-object-v1-response-mpayload';

/**
 * 
 * @export
 * @interface UsergroupmembershipCreateObjectV1ResponseAllOf
 */
export interface UsergroupmembershipCreateObjectV1ResponseAllOf {
    /**
     * 
     * @type {UsergroupmembershipCreateObjectV1ResponseMPayload}
     * @memberof UsergroupmembershipCreateObjectV1ResponseAllOf
     */
    'mPayload': UsergroupmembershipCreateObjectV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUsergroupmembershipCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectUsergroupmembershipCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A UsergroupmembershipCreateObjectV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupmembershipCreateObjectV1ResponseAllOf
 */
export class DataObjectUsergroupmembershipCreateObjectV1ResponseAllOf {
   mPayload:UsergroupmembershipCreateObjectV1ResponseMPayload = new DataObjectUsergroupmembershipCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A UsergroupmembershipCreateObjectV1ResponseAllOf Validation Object
 * @class ValidationObjectUsergroupmembershipCreateObjectV1ResponseAllOf
 */
export class ValidationObjectUsergroupmembershipCreateObjectV1ResponseAllOf {
   mPayload = new ValidationObjectUsergroupmembershipCreateObjectV1ResponseMPayload()
} 


