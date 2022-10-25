/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignfoldersignerassociationRequest } from './ezsignfoldersignerassociation-request';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignfoldersignerassociationRequestCompound } from './ezsignfoldersignerassociation-request-compound';

import { DefaultObject } from '../base'

/**
 * Request for POST /1/object/ezsignfoldersignerassociation
 * @export
 * @interface EzsignfoldersignerassociationCreateObjectV1Request
 */
export interface EzsignfoldersignerassociationCreateObjectV1Request {
    /**
     * 
     * @type {EzsignfoldersignerassociationRequest}
     * @memberof EzsignfoldersignerassociationCreateObjectV1Request
     */
    'objEzsignfoldersignerassociation'?: EzsignfoldersignerassociationRequest;
    /**
     * 
     * @type {EzsignfoldersignerassociationRequestCompound}
     * @memberof EzsignfoldersignerassociationCreateObjectV1Request
     */
    'objEzsignfoldersignerassociationCompound'?: EzsignfoldersignerassociationRequestCompound;
}
/**
 * A EzsignfoldersignerassociationCreateObjectV1Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfoldersignerassociationCreateObjectV1Request
 */
export class DefaultObjectEzsignfoldersignerassociationCreateObjectV1Request extends DefaultObject {
   objEzsignfoldersignerassociation?:Partial<EzsignfoldersignerassociationRequest> = undefined
   objEzsignfoldersignerassociationCompound?:Partial<EzsignfoldersignerassociationRequestCompound> = undefined
}


