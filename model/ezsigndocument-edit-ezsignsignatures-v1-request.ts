/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignatureRequestCompound } from './ezsignsignature-request-compound';

import { DefaultObject } from '../base'

/**
 * Request for PUT /1/object/ezsigndocument/{pkiEzsigndocumentID}/editEzsignsignatures
 * @export
 * @interface EzsigndocumentEditEzsignsignaturesV1Request
 */
export interface EzsigndocumentEditEzsignsignaturesV1Request {
    /**
     * 
     * @type {Array<EzsignsignatureRequestCompound>}
     * @memberof EzsigndocumentEditEzsignsignaturesV1Request
     */
    'a_objEzsignsignature': Array<EzsignsignatureRequestCompound>;
}
/**
 * A EzsigndocumentEditEzsignsignaturesV1Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigndocumentEditEzsignsignaturesV1Request
 */
export class DefaultObjectEzsigndocumentEditEzsignsignaturesV1Request extends DefaultObject {
   a_objEzsignsignature:Array<EzsignsignatureRequestCompound> = []
}


