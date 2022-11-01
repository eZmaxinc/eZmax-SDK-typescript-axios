/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * Definition of objSQLQuery Object
 * @export
 * @interface CommonResponseObjSQLQuery
 */
export interface CommonResponseObjSQLQuery {
    /**
     * The SQL Query
     * @type {string}
     * @memberof CommonResponseObjSQLQuery
     */
    'sQuery': string;
    /**
     * Execution time of the SQL Query in seconds
     * @type {number}
     * @memberof CommonResponseObjSQLQuery
     */
    'fDuration': number;
}
/**
 * A CommonResponseObjSQLQuery Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCommonResponseObjSQLQuery
 */
export class DefaultObjectCommonResponseObjSQLQuery extends DefaultObject {
   sQuery:string = ''
   fDuration:number = 0
}


