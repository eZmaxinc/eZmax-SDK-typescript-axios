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
 * A Contactinformations Object
 * @export
 * @interface ContactinformationsRequest
 */
export interface ContactinformationsRequest {
    /**
     * The index in the a_objAddress array (zero based index) representing the Address object that should become the default one.  You can leave the value to 0 if the array is empty.
     * @type {number}
     * @memberof ContactinformationsRequest
     */
    iAddressDefault: number;
    /**
     * The index in the a_objPhone array (zero based index) representing the Phone object that should become the default one.  You can leave the value to 0 if the array is empty.
     * @type {number}
     * @memberof ContactinformationsRequest
     */
    iPhoneDefault: number;
    /**
     * The index in the a_objEmail array (zero based index) representing the Email object that should become the default one.  You can leave the value to 0 if the array is empty.
     * @type {number}
     * @memberof ContactinformationsRequest
     */
    iEmailDefault: number;
    /**
     * The index in the a_objWebsite array (zero based index) representing the Website object that should become the default one.  You can leave the value to 0 if the array is empty.
     * @type {number}
     * @memberof ContactinformationsRequest
     */
    iWebsiteDefault: number;
}
