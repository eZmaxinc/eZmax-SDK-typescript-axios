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
import { EzsigndocumentRequest } from './ezsigndocument-request';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigndocumentRequestCompound } from './ezsigndocument-request-compound';

import { DefaultObject } from '../base'

/**
 * Request for POST /1/object/ezsigndocument
 * @export
 * @interface EzsigndocumentCreateObjectV1Request
 */
export interface EzsigndocumentCreateObjectV1Request {
    /**
     * 
     * @type {EzsigndocumentRequest}
     * @memberof EzsigndocumentCreateObjectV1Request
     */
    'objEzsigndocument'?: EzsigndocumentRequest;
    /**
     * 
     * @type {EzsigndocumentRequestCompound}
     * @memberof EzsigndocumentCreateObjectV1Request
     */
    'objEzsigndocumentCompound'?: EzsigndocumentRequestCompound;
}
/**
 * A EzsigndocumentCreateObjectV1Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigndocumentCreateObjectV1Request
 */
export class DefaultObjectEzsigndocumentCreateObjectV1Request extends DefaultObject {
   objEzsigndocument?:Partial<EzsigndocumentRequest> = undefined
   objEzsigndocumentCompound?:Partial<EzsigndocumentRequestCompound> = undefined
}


