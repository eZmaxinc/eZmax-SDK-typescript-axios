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



import { DefaultObject } from '../base'

/**
 * Request for POST /1/object/ezsignbulksend/{pkiEzsignbulksendID}/reorder
 * @export
 * @interface EzsignbulksendReorderV1Request
 */
export interface EzsignbulksendReorderV1Request {
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsignbulksendReorderV1Request
     */
    'a_pkiEzsignbulksenddocumentmappingID': Array<number>;
}
/**
 * A EzsignbulksendReorderV1Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignbulksendReorderV1Request
 */
export class DefaultObjectEzsignbulksendReorderV1Request extends DefaultObject {
   a_pkiEzsignbulksenddocumentmappingID:Array<number> = []
}


