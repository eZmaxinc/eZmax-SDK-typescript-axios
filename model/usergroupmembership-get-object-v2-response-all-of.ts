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
import { UsergroupmembershipGetObjectV2ResponseMPayload } from './usergroupmembership-get-object-v2-response-mpayload';

/**
 * 
 * @export
 * @interface UsergroupmembershipGetObjectV2ResponseAllOf
 */
export interface UsergroupmembershipGetObjectV2ResponseAllOf {
    /**
     * 
     * @type {UsergroupmembershipGetObjectV2ResponseMPayload}
     * @memberof UsergroupmembershipGetObjectV2ResponseAllOf
     */
    'mPayload': UsergroupmembershipGetObjectV2ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUsergroupmembershipGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectUsergroupmembershipGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A UsergroupmembershipGetObjectV2ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupmembershipGetObjectV2ResponseAllOf
 */
export class DataObjectUsergroupmembershipGetObjectV2ResponseAllOf {
   mPayload:UsergroupmembershipGetObjectV2ResponseMPayload = new DataObjectUsergroupmembershipGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A UsergroupmembershipGetObjectV2ResponseAllOf Validation Object
 * @class ValidationObjectUsergroupmembershipGetObjectV2ResponseAllOf
 */
export class ValidationObjectUsergroupmembershipGetObjectV2ResponseAllOf {
   mPayload = new ValidationObjectUsergroupmembershipGetObjectV2ResponseMPayload()
} 


