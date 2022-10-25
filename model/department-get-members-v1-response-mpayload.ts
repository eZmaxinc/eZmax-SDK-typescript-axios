/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * Payload for GET /1/object/department/{pkiDepartmentID}/getMembers
 * @export
 * @interface DepartmentGetMembersV1ResponseMPayload
 */
export interface DepartmentGetMembersV1ResponseMPayload {
    /**
     * 
     * @type {Array<number>}
     * @memberof DepartmentGetMembersV1ResponseMPayload
     */
    'a_fkiAgentID'?: Array<number>;
    /**
     * 
     * @type {Array<number>}
     * @memberof DepartmentGetMembersV1ResponseMPayload
     */
    'a_fkiBrokerID'?: Array<number>;
    /**
     * 
     * @type {Array<number>}
     * @memberof DepartmentGetMembersV1ResponseMPayload
     */
    'a_fkiCustomerID'?: Array<number>;
    /**
     * 
     * @type {Array<number>}
     * @memberof DepartmentGetMembersV1ResponseMPayload
     */
    'a_fkiEmployeeID'?: Array<number>;
}
/**
 * A DepartmentGetMembersV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectDepartmentGetMembersV1ResponseMPayload
 */
export class DefaultObjectDepartmentGetMembersV1ResponseMPayload extends DefaultObject {
   a_fkiAgentID?:Array<number> = undefined
   a_fkiBrokerID?:Array<number> = undefined
   a_fkiCustomerID?:Array<number> = undefined
   a_fkiEmployeeID?:Array<number> = undefined
}


