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
import { FranchisereferalincomeCreateObjectV1ResponseMPayload } from './franchisereferalincome-create-object-v1-response-mpayload';

/**
 * 
 * @export
 * @interface FranchisereferalincomeCreateObjectV1ResponseAllOf
 */
export interface FranchisereferalincomeCreateObjectV1ResponseAllOf {
    /**
     * 
     * @type {FranchisereferalincomeCreateObjectV1ResponseMPayload}
     * @memberof FranchisereferalincomeCreateObjectV1ResponseAllOf
     */
    'mPayload': FranchisereferalincomeCreateObjectV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectFranchisereferalincomeCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectFranchisereferalincomeCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A FranchisereferalincomeCreateObjectV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectFranchisereferalincomeCreateObjectV1ResponseAllOf
 */
export class DataObjectFranchisereferalincomeCreateObjectV1ResponseAllOf {
   mPayload:FranchisereferalincomeCreateObjectV1ResponseMPayload = new DataObjectFranchisereferalincomeCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A FranchisereferalincomeCreateObjectV1ResponseAllOf Validation Object
 * @class ValidationObjectFranchisereferalincomeCreateObjectV1ResponseAllOf
 */
export class ValidationObjectFranchisereferalincomeCreateObjectV1ResponseAllOf {
   mPayload = new ValidationObjectFranchisereferalincomeCreateObjectV1ResponseMPayload()
} 


