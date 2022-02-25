/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.5
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



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

