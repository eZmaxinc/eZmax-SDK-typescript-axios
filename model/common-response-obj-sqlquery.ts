/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



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
