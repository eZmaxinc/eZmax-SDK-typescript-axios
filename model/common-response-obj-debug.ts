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
import { CommonResponseObjSQLQuery } from './common-response-obj-sqlquery';

/**
 * This is a generic debug object that is returned by all API requests
 * @export
 * @interface CommonResponseObjDebug
 */
export interface CommonResponseObjDebug {
    /**
     * The peak memory allocated during the API request execution. Formatted as a human readable string
     * @type {string}
     * @memberof CommonResponseObjDebug
     */
    'sMemoryUsage': string;
    /**
     * The total server execution time of the API request execution. Formatted as a human readable string
     * @type {string}
     * @memberof CommonResponseObjDebug
     */
    'sRunTime': string;
    /**
     * The number of SQL SELECT queries that were sent to the database server during the API request execution
     * @type {number}
     * @memberof CommonResponseObjDebug
     */
    'iSQLSelects': number;
    /**
     * The number of SQL INSERT/UPDATE/DELETE queries that were sent to the database server during the API request execution
     * @type {number}
     * @memberof CommonResponseObjDebug
     */
    'iSQLQueries': number;
    /**
     * An array of the SQL Queries that were executed during the API request execution
     * @type {Array<CommonResponseObjSQLQuery>}
     * @memberof CommonResponseObjDebug
     */
    'a_objSQLQuery': Array<CommonResponseObjSQLQuery>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CommonResponseObjDebug Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommonResponseObjDebug
 */
export class DataObjectCommonResponseObjDebug {
   sMemoryUsage:string = ''
   sRunTime:string = ''
   iSQLSelects:number = 0
   iSQLQueries:number = 0
   a_objSQLQuery:Array<CommonResponseObjSQLQuery> = []
}

/**
 * @export 
 * A CommonResponseObjDebug Validation Object
 * @class ValidationObjectCommonResponseObjDebug
 */
export class ValidationObjectCommonResponseObjDebug {
   sMemoryUsage = {
      type: 'string',
      required: true
   }
   sRunTime = {
      type: 'string',
      required: true
   }
   iSQLSelects = {
      type: 'integer',
      required: true
   }
   iSQLQueries = {
      type: 'integer',
      required: true
   }
   a_objSQLQuery = {
      type: 'array',
      required: true
   }
} 


