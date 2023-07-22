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
import { EzmaxinvoicingResponseCompound } from './ezmaxinvoicing-response-compound';

/**
 * Payload for GET /2/object/ezmaxinvoicing/{pkiEzmaxinvoicingID}
 * @export
 * @interface EzmaxinvoicingGetObjectV2ResponseMPayload
 */
export interface EzmaxinvoicingGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {EzmaxinvoicingResponseCompound}
     * @memberof EzmaxinvoicingGetObjectV2ResponseMPayload
     */
    'objEzmaxinvoicing': EzmaxinvoicingResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzmaxinvoicingResponseCompound } from './'
// @ts-ignore
import { ValidationObjectEzmaxinvoicingResponseCompound } from './'

/**
 * @export 
 * A EzmaxinvoicingGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzmaxinvoicingGetObjectV2ResponseMPayload
 */
export class DataObjectEzmaxinvoicingGetObjectV2ResponseMPayload {
   objEzmaxinvoicing:EzmaxinvoicingResponseCompound = new DataObjectEzmaxinvoicingResponseCompound()
}

/**
 * @export 
 * A EzmaxinvoicingGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectEzmaxinvoicingGetObjectV2ResponseMPayload
 */
export class ValidationObjectEzmaxinvoicingGetObjectV2ResponseMPayload {
   objEzmaxinvoicing = new ValidationObjectEzmaxinvoicingResponseCompound()
} 


