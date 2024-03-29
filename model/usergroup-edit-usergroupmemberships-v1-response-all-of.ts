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
import { UsergroupEditUsergroupmembershipsV1ResponseMPayload } from './usergroup-edit-usergroupmemberships-v1-response-mpayload';

/**
 * 
 * @export
 * @interface UsergroupEditUsergroupmembershipsV1ResponseAllOf
 */
export interface UsergroupEditUsergroupmembershipsV1ResponseAllOf {
    /**
     * 
     * @type {UsergroupEditUsergroupmembershipsV1ResponseMPayload}
     * @memberof UsergroupEditUsergroupmembershipsV1ResponseAllOf
     */
    'mPayload': UsergroupEditUsergroupmembershipsV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUsergroupEditUsergroupmembershipsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectUsergroupEditUsergroupmembershipsV1ResponseMPayload } from './'

/**
 * @export 
 * A UsergroupEditUsergroupmembershipsV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupEditUsergroupmembershipsV1ResponseAllOf
 */
export class DataObjectUsergroupEditUsergroupmembershipsV1ResponseAllOf {
   mPayload:UsergroupEditUsergroupmembershipsV1ResponseMPayload = new DataObjectUsergroupEditUsergroupmembershipsV1ResponseMPayload()
}

/**
 * @export 
 * A UsergroupEditUsergroupmembershipsV1ResponseAllOf Validation Object
 * @class ValidationObjectUsergroupEditUsergroupmembershipsV1ResponseAllOf
 */
export class ValidationObjectUsergroupEditUsergroupmembershipsV1ResponseAllOf {
   mPayload = new ValidationObjectUsergroupEditUsergroupmembershipsV1ResponseMPayload()
} 


