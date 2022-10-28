/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * Generic List Response
 * @export
 * @interface CommonGetListV1ResponseMPayload
 */
export interface CommonGetListV1ResponseMPayload {
    /**
     * The number of rows returned
     * @type {number}
     * @memberof CommonGetListV1ResponseMPayload
     */
    'iRowReturned': number;
    /**
     * The number of rows matching your filters (if any) or the total number of rows
     * @type {number}
     * @memberof CommonGetListV1ResponseMPayload
     */
    'iRowFiltered': number;
}
/**
 * A CommonGetListV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCommonGetListV1ResponseMPayload
 */
export class DefaultObjectCommonGetListV1ResponseMPayload extends DefaultObject {
   iRowReturned:number = 0
   iRowFiltered:number = 0
}


