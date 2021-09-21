/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.0.48
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { EzsigndocumentRequest } from './ezsigndocument-request';
import { EzsigndocumentRequestCompound } from './ezsigndocument-request-compound';



/**
 * Request for the /1/object/ezsigndocument/createObject API Request
 * @export
 * @interface EzsigndocumentCreateObjectV1Request
 */
export interface EzsigndocumentCreateObjectV1Request {
    /**
     * 
     * @type {EzsigndocumentRequest}
     * @memberof EzsigndocumentCreateObjectV1Request
     */
    objEzsigndocument?: EzsigndocumentRequest;
    /**
     * 
     * @type {EzsigndocumentRequestCompound}
     * @memberof EzsigndocumentCreateObjectV1Request
     */
    objEzsigndocumentCompound?: EzsigndocumentRequestCompound;
}
