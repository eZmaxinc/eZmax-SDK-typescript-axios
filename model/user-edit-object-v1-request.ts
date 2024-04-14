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
import { UserRequestCompound } from './user-request-compound';

/**
 * Request for PUT /1/object/user/{pkiUserID}
 * @export
 * @interface UserEditObjectV1Request
 */
export interface UserEditObjectV1Request {
    /**
     * 
     * @type {UserRequestCompound}
     * @memberof UserEditObjectV1Request
     */
    /*'objUser': UserRequestCompound;*/
    'objUser': UserRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUserRequestCompound } from './'
// @ts-ignore
import { ValidationObjectUserRequestCompound } from './'

/**
 * @export 
 * A UserEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserEditObjectV1Request
 */
export class DataObjectUserEditObjectV1Request {
   objUser:UserRequestCompound = new DataObjectUserRequestCompound()
}

/**
 * @export 
 * A UserEditObjectV1Request Validation Object
 * @class ValidationObjectUserEditObjectV1Request
 */
export class ValidationObjectUserEditObjectV1Request {
   objUser = new ValidationObjectUserRequestCompound()
} 


